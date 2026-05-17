//! Intel e1000e NIC driver (82574L / 82579 / I217 / I218 / I219 family)
//!
//! Register semantics and hot paths are aligned with the in-tree Linux driver
//! in this repo (`e1000e/*.c`, especially `netdev.c` ring setup, `hw.h` RX
//! extended descriptors, and `defines.h` interrupt masks). A full line-by-line
//! port of all MAC/PHY/NVM paths is not the goal; behaviour-critical pieces are
//! matched so bare-metal hardware matches QEMU/Linux expectations.
//!
//! Set [`E1000E_CONVENTIONAL`] for a minimal profile: no checksum offload, no
//! IAME, no optional PCH tuning, short link-up wait. RX always uses extended
//! descriptors (`RFCTL_EXTEN`) — I219/PCH ignore legacy layout on real silicon.

/// Minimal NIC profile for bare-metal bring-up (fewer moving parts).
const E1000E_CONVENTIONAL: bool = true;
/// Bump when changing init/RX paths — grep dmesg for this tag to verify the ISO.
const E1000E_DRIVER_TAG: &str = "e1000e-rev-20250517-rx8";

#[inline]
const fn e1000e_profile() -> &'static str {
    if E1000E_CONVENTIONAL {
        "conventional"
    } else {
        "extended"
    }
}

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::mem::size_of;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, Ordering};

use smoltcp::iface::*;
use smoltcp::phy::{self, DeviceCapabilities};
use smoltcp::time::Instant;
use smoltcp::wire::*;
use smoltcp::Result as SmolResult;

use crate::net::get_sockets;
use crate::scheme::{NetScheme, Scheme, SchemeUpcast, RouteInfo, NetStats};
use crate::{Device, DeviceError, DeviceResult};
use crate::bus::pci_drivers::PciDriver;
use crate::builder::IoMapper;
use crate::utils::dma::DmaRegion;
use pci::{PCIDevice, BAR, Location};
use crate::bus::pci::{PortOpsImpl, PCI_ACCESS};
use lock::Mutex;


use super::{timer_now_as_micros, intr_on, intr_off, intr_get};

// ---------------------------------------------------------------------------
// Register offsets (byte addresses / 4 → u32 index)
// ---------------------------------------------------------------------------
const E1000E_CTRL: usize = 0x0000 / 4;
const E1000E_STATUS: usize = 0x0008 / 4;
const E1000E_MDIC: usize = 0x0020 / 4;
const E1000E_EXTCNF_CTRL: usize = 0x0F00 / 4;
const E1000E_EECD: usize = 0x0010 / 4;
const E1000E_VFTA_BASE: usize = 0x5600 / 4; // VLAN Filter Table Array (128 × u32)
const E1000E_EERD: usize = 0x0014 / 4;
const E1000E_ICR: usize = 0x00C0 / 4;
const E1000E_ITR: usize = 0x00C4 / 4; // Interrupt Throttling Rate
const E1000E_IMS: usize = 0x00D0 / 4;
const E1000E_IMC: usize = 0x00D8 / 4;
const E1000E_IAM: usize = 0x00E0 / 4; // Interrupt Acknowledge Auto Mask (Linux e1000_configure_rx)
const E1000E_RCTL: usize = 0x0100 / 4;
const E1000E_TCTL: usize = 0x0400 / 4;
const E1000E_TIPG: usize = 0x0410 / 4;
// Receive descriptor ring queue 0.  0x2800 is correct for all e1000e silicon;
// queues ≥4 use 0xC400 + 0x100*(n-4), but this driver only uses queue 0.
const E1000E_RDBAL: usize = 0x2800 / 4;
const E1000E_RDBAH: usize = 0x2804 / 4;
const E1000E_RDLEN: usize = 0x2808 / 4;
const E1000E_RDTR: usize = 0x2820 / 4; // RX Delay Timer
const E1000E_RADV: usize = 0x282C / 4; // RX Absolute Delay Timer
const E1000E_RDH: usize = 0x2810 / 4;
const E1000E_RDT: usize = 0x2818 / 4;
// Transmit descriptor ring
const E1000E_TDBAL: usize = 0x3800 / 4;
const E1000E_TDBAH: usize = 0x3804 / 4;
const E1000E_TDLEN: usize = 0x3808 / 4;
const E1000E_TDH: usize = 0x3810 / 4;
const E1000E_TDT: usize = 0x3818 / 4;
// Receive address
const E1000E_RAL0: usize = 0x5400 / 4;
const E1000E_RAH0: usize = 0x5404 / 4;
// Multicast table (128 × u32)
const E1000E_MTA_BASE: usize = 0x5200 / 4;
const E1000E_MTA_LEN: usize = 128;
// Statistics (regs.h) — clear-on-read; used for ifconfig /proc/net/dev.
const E1000E_GPRC: usize = 0x04074 / 4;
const E1000E_GPTC: usize = 0x04080 / 4;
const E1000E_GORCL: usize = 0x04088 / 4;
const E1000E_GORCH: usize = 0x0408C / 4;
const E1000E_GOTCL: usize = 0x04090 / 4;
const E1000E_GOTCH: usize = 0x04094 / 4;
const E1000E_MPC: usize = 0x04010 / 4;

// Additional registers for offloading/filtering
const E1000E_VET: usize = 0x0038 / 4;
const E1000E_RXCSUM: usize = 0x5000 / 4;
const E1000E_RFCTL: usize = 0x5008 / 4;
const E1000E_MRQC: usize = 0x5818 / 4;
const E1000E_FEXTNVM6: usize = 0x01014 / 4;
const E1000E_FEXTNVM7: usize = 0x01018 / 4;
const E1000E_FEXTNVM11: usize = 0x05BBC / 4;
const E1000E_KMRNCTRLSTA: usize = 0x00034 / 4;
const E1000E_PBA: usize = 0x01000 / 4;
const E1000E_WUC: usize = 0x05800 / 4;
const E1000E_FCTTV: usize = 0x00170 / 4;
const E1000E_FCRTV: usize = 0x05F40 / 4;
const E1000E_FCRTL: usize = 0x02160 / 4;
const E1000E_FCRTH: usize = 0x02168 / 4;
const E1000E_TARC0: usize = 0x03840 / 4;
const E1000E_TARC1: usize = 0x03940 / 4;
const E1000E_TXDCTL: usize = 0x03828 / 4;
/// Linux `e1000_configure_tx`: mirror TXDCTL(0) to queue 1 (`ew32(TXDCTL(1), er32(TXDCTL(0)))`).
const E1000E_TXDCTL1: usize = E1000E_TXDCTL + (0x100 / 4);
const E1000E_TIDV: usize = 0x03820 / 4;
const E1000E_TADV: usize = 0x0382C / 4;
const E1000E_RXDCTL: usize = 0x02828 / 4;
const E1000E_SRRCTL: usize = 0x02100 / 4;
const E1000E_FEXTNVM4: usize = 0x000E0 / 4;
const E1000E_FEXTNVM9: usize = 0x05BB4 / 4;
const E1000E_PBECCSTS: usize = 0x0100C / 4;
const E1000E_CTRL_EXT: usize = 0x00018 / 4;
const E1000E_CRC_OFFSET: usize = 0x05F50 / 4;
const E1000E_KABGTXD: usize = 0x03004 / 4;
const E1000E_IOSFPC: usize = 0x00F28 / 4;
const E1000E_FWSM: usize = 0x05B54 / 4;
const E1000E_WUFC: usize = 0x05808 / 4;
const E1000E_WUS: usize = 0x05810 / 4;
const E1000E_FEXTNVM3: usize = 0x0003C / 4;
const E1000E_H2ME: usize = 0x05B50 / 4;
const E1000E_MANC: usize = 0x05820 / 4;


// RFCTL (Linux e1000e/defines.h): EXTEN enables extended RX descriptor write-back
// (union e1000_rx_desc_extended in hw.h — DD/status in u32 @ +8, length u16 @ +12).
const RFCTL_EXTEN: u32 = 1 << 15; // E1000_RFCTL_EXTEN
// E1000_RXD_STAT_* apply to the low byte of wb.upper.status_error (full dword in staterr).
const RXD_EXT_DD: u32 = 0x01;
const RXD_EXT_EOP: u32 = 0x02;
/// Linux `E1000_CTRL_EXT_IAME` — reading ICR masks until IMS is written again.
const CTRL_EXT_IAME: u32 = 1 << 27;
/// Linux `e1000_irq_enable` (PCH): `IMS_ENABLE_MASK | E1000_IMS_ECCER`.
const IMS_REARM_LINUX: u32 = (1 << 0)   // TXDW
    | (1 << 2)   // LSC
    | (1 << 3)   // RXSEQ
    | (1 << 4)   // RXDMT0
    | (1 << 7)   // RXT0
    | (1 << 22); // ECCER
/// Conventional mode: RX + link-change only (no auto-mask via IAME).
const IMS_CONVENTIONAL: u32 = (1 << 7) | (1 << 2); // RXT0 | LSC

// KABGTXD bits
const KABGTXD_BGSQLBIAS: u32 = 0x00050000;

// FEXTNVM6 bits
const FEXTNVM6_K1_OFF_EN: u32 = 1 << 31;
const FEXTNVM6_DIS_ELDW: u32 = 1 << 5; // Disable Early Link Down Window

// KMRNCTRLSTA bits for ICH8/PCH
const KMRNCTRLSTA_OFFSET_SHIFT: u32 = 16;
const KMRNCTRLSTA_REN: u32 = 1 << 21;
const KMRNCTRLSTA_WEN: u32 = 1 << 22;
const KMRNCTRLSTA_K1_CONFIG: u16 = 0x1F; // Index 0x1F
const KMRNCTRLSTA_K1_ENABLE: u16 = 1 << 13;
const KMRNCTRLSTA_TIMEOUTS: u16 = 0x4;
const KMRNCTRLSTA_INBAND_PARAM: u16 = 0x9;
const E1000E_GCR: usize = 0x05B00 / 4;
const E1000E_FFLT_DBG: usize = 0x05F04 / 4;
/// Linux `PCIE_NO_SNOOP_ALL` — GCR bits 0..5.
const GCR_PCIE_NO_SNOOP_ALL: u32 = 0x3F;
const FFLT_DBG_DONT_GATE_WAKE_DMA_CLK: u32 = 1 << 12;
const I217_PLL_CLOCK_GATE_MASK: u16 = 0x07FF;
/// Linux `SPEED_*` (mbps) for TIPG/EMI paths in ich8lan.c.
const SPEED_10: u32 = 10;
const SPEED_100: u32 = 100;
const SPEED_1000: u32 = 1000;
const PHY_EMI_ADDR: u32 = 0x10;
const PHY_EMI_DATA: u32 = 0x11;
const I217_RX_CONFIG_EMI: u16 = 0xB20C;
const I82577_CFG_REG: u32 = 22;
const I82577_CFG_ASSERT_CRS_ON_TX: u16 = 1 << 15;
const I82577_CFG_ENABLE_DOWNSHIFT: u16 = 3 << 10;

// CTRL bits
const CTRL_FD: u32 = 1 << 0; // full duplex
const CTRL_SLU: u32 = 1 << 6; // set link up
const CTRL_ASDE: u32 = 1 << 5; // auto-speed detection enable
const CTRL_RST: u32 = 1 << 26; // full MAC + PHY reset
const CTRL_PHY_RST: u32 = 1 << 31; // PHY-only reset (Linux E1000_CTRL_PHY_RST)
const CTRL_TFCE: u32 = 1 << 27; // Transmit Flow Control Enable
const CTRL_RFCE: u32 = 1 << 28; // Receive Flow Control Enable
const CTRL_VME: u32 = 1 << 30; // VLAN Mode Enable
const CTRL_GIO_MASTER_DISABLE: u32 = 1 << 2; // GIO Master Disable
const CTRL_LANPHYPC_OVERRIDE: u32 = 0x00010000;
const CTRL_LANPHYPC_VALUE: u32 = 0x00020000;
const CTRL_SPD_1000: u32 = 1 << 9;
const CTRL_SPD_100: u32 = 1 << 8;
const CTRL_FRCSPD: u32 = 1 << 12;
const CTRL_FRCDPX: u32 = 1 << 11;
const CTRL_ILOS: u32 = 1 << 7; // Invert Loss of Signal


// CTRL_EXT bits
const CTRL_EXT_RO_DIS: u32 = 1 << 2; // Relaxation Order Disable
const CTRL_EXT_PHYPDEN: u32 = 1 << 20; // PHY Power Down Enable
const CTRL_EXT_DPG_EN: u32 = 1 << 3; // Dynamic Power Gating Enable
const CTRL_EXT_SPD_BYPS: u32 = 1 << 15; // Speed-select bypass (Linux k1/speed pulse)
const IGP_PHY_PAGE_SELECT: u32 = 31;
const MAX_PHY_MULTI_PAGE_REG: u32 = 0xF;
const PHY_REG_770_19: u32 = (770 << 5) | 19; // IGP3_KMRN_DIAG — link stall fix

// FEXTNVM4 bits
const FEXTNVM4_BEACON_DURATION_8USEC: u32 = 0x7;
const FEXTNVM4_BEACON_DURATION_MASK: u32 = 0x7;

// FEXTNVM7 bits
const FEXTNVM7_SIDE_CLK_UNGATE: u32 = 1 << 2;
const FEXTNVM7_DISABLE_SMB_PERST: u32 = 1 << 5;
const FEXTNVM7_NEED_DESCR_RING_FLUSH: u32 = 1 << 16;
// Do NOT set bit 28 here — not in Linux e1000e; on I219 it breaks broadcast RX (DHCP).
const RFCTL_NFSW_DIS: u32 = 1 << 6; // Linux ich8: disable NFS write filter
const RFCTL_NFSR_DIS: u32 = 1 << 7; // Linux ich8: disable NFS read filter

// FEXTNVM9 bits
const FEXTNVM9_IOSFSB_CLKGATE_DIS: u32 = 1 << 11;
const FEXTNVM9_IOSFSB_CLKREQ_DIS: u32 = 1 << 12;

// FEXTNVM11 bits
const FEXTNVM11_DISABLE_L1_2: u32 = 1 << 1;
const FEXTNVM11_DISABLE_MULR_FIX: u32 = 1 << 13;

// TXDCTL bits
const TXDCTL_GRAN: u32 = 1 << 24; // 0=cache lines, 1=descriptors
const TXDCTL_FULL_TX_DESC_WB: u32 = 1 << 26;
const TXDCTL_COUNT_DESC: u32 = 1 << 22; // bit 22 must be 1 on ICH8+
const TXDCTL_QUEUE_ENABLE: u32 = 1 << 25; // PCH-SPT (I219) and later: must be set to enable TX DMA

// RXDCTL bits
const RXDCTL_QUEUE_ENABLE: u32 = 1 << 25; // PCH-SPT (I219) and later: must be set to enable RX DMA
/// Linux `E1000_RXDCTL_DMA_BURST_ENABLE` (netdev.c / e1000.h).
const RXDCTL_DMA_BURST: u32 = 0x0100_0000 | (4 << 16) | (4 << 8) | 0x20;
const RDTR_FPD: u32 = 1 << 31;
const CTRL_MEHE: u32 = 1 << 19;
const PBECCSTS_ECC_ENABLE: u32 = 1 << 16;
const RFCTL_IPV6_EX_DIS: u32 = 1 << 16;
const RFCTL_NEW_IPV6_EXT_DIS: u32 = 1 << 17;

// STATUS bits
const STATUS_LU: u32 = 1 << 1; // link up
const STATUS_LAN_INIT_DONE: u32 = 1 << 9; // LAN init from NVM completed (ICH10+)
const STATUS_PHYRA: u32 = 1 << 10; // PHY Reset Asserted — must clear after PHY_RST
const STATUS_GIO_MASTER_ENABLE: u32 = 1 << 19; // GIO Master Enable Status
const STATUS_SPEED_MASK: u32 = 0x000000C0;
const STATUS_SPEED_1000: u32 = 0x00000080;
const STATUS_SPEED_100: u32 = 0x00000040;
const STATUS_FD: u32 = 1 << 0;

// EXTCNF_CTRL (PCH PHY / NVM shared access)
const EXTCNF_CTRL_SWFLAG: u32 = 0x20;
const EXTCNF_CTRL_GATE_PHY_CFG: u32 = 0x80;

// EERD bits (discrete e1000e like 82574L use bit 4 for DONE; PCH-integrated like I219 use bit 1)
const EERD_START: u32 = 1 << 0;
const EERD_DONE_BIT4: u32 = 1 << 4;
const EERD_DONE_BIT1: u32 = 1 << 1;
const EERD_DATA_SHIFT: u32 = 16;

const PCICFG_DESC_RING_STATUS: u16 = 0xE4;
const FLUSH_DESC_REQUIRED: u16 = 0x100;

// MDIO / MDIC (Clause 22 access to integrated PHY)
const MDIC_REG_SHIFT: u32 = 16;
const MDIC_PHY_SHIFT: u32 = 21;
const MDIC_OP_READ: u32 = 0x0800_0000;
const MDIC_OP_WRITE: u32 = 0x0400_0000;
const MDIC_READY: u32 = 0x1000_0000;
const MDIC_ERROR: u32 = 0x4000_0000;
const MII_BMCR: u32 = 0x00;
const MII_BMSR: u32 = 0x01;
const MII_ADVERTISE: u32 = 0x04;
const MII_CTRL1000: u32 = 0x09;
const BMCR_ANENABLE: u16 = 0x1000;
const BMCR_ANRESTART: u16 = 0x0200;
const ADVERTISE_CSMA: u16 = 0x0001;
const ADVERTISE_10HALF: u16 = 0x0020;
const ADVERTISE_10FULL: u16 = 0x0040;
const ADVERTISE_100HALF: u16 = 0x0080;
const ADVERTISE_100FULL: u16 = 0x0100;
const ADVERTISE_PAUSE_CAP: u16 = 0x0400;
const ADVERTISE_PAUSE_ASYM: u16 = 0x0800;
const ADVERTISE_ALL_COPPER: u16 = ADVERTISE_CSMA
    | ADVERTISE_10HALF
    | ADVERTISE_10FULL
    | ADVERTISE_100HALF
    | ADVERTISE_100FULL
    | ADVERTISE_PAUSE_CAP
    | ADVERTISE_PAUSE_ASYM;
const ADVERTISE_1000FULL: u16 = 0x0200;
/// I82577/I217/I219 PHY status 2 (Linux `I82577_PHY_STATUS_2`).
const MII_PHY_STATUS_2: u32 = 26;
const PHY_STATUS2_SPEED_MASK: u16 = 0x0300;
const PHY_STATUS2_SPEED_1000: u16 = 0x0200;
const PHY_STATUS2_SPEED_100: u16 = 0x0100;

// STATUS-ready poll: 150 ms covers PCH-based NICs (I217/I218/I219).
const STATUS_POLL_US: u64 = 150_000;
// NVM EERD-done poll: 10 ms is more than enough for any e1000e silicon.
const NVM_POLL_US: u64 = 10_000;

// RCTL bits (e1000e/defines.h, e1000_setup_rctl in netdev.c)
const RCTL_EN: u32 = 1 << 1;
const RCTL_SBP: u32 = 1 << 2; // store bad packets
const RCTL_UPE: u32 = 1 << 3;
const RCTL_MPE: u32 = 1 << 4;
const RCTL_LPE: u32 = 1 << 5; // long packet enable (jumbo)
const RCTL_DTYP_PS: u32 = 1 << 10; // packet-split descriptor type
const RCTL_MO_MASK: u32 = 0x3 << 12; // multicast offset
const RCTL_BAM: u32 = 1 << 15; // broadcast accept
const RCTL_RX_SZ_MASK: u32 = 0x3 << 16; // buffer size field when BSEX=0
const RCTL_VFE: u32 = 1 << 18; // VLAN Filter Enable
const RCTL_BSEX: u32 = 1 << 25; // buffer size extension
const RCTL_SECRC: u32 = 1 << 26; // strip CRC

// TCTL bits
const TCTL_EN: u32 = 1 << 1;
const TCTL_PSP: u32 = 1 << 3;
const TCTL_RTLC: u32 = 1 << 24; // E1000_TCTL_RTLC — Linux e1000_configure_tx
const TCTL_CT_SHIFT: u32 = 4;
const TCTL_CT_LINUX: u32 = 15 << TCTL_CT_SHIFT; // E1000_COLLISION_THRESHOLD
const TCTL_COLD_LINUX: u32 = 63 << 12; // E1000_COLLISION_DISTANCE << E1000_COLD_SHIFT

const TX_CMD_EOP: u8 = 1 << 0;
const TX_CMD_IFCS: u8 = 1 << 1;
const TX_CMD_RS: u8 = 1 << 3;

const NUM_RX: usize = 256;
const NUM_TX: usize = 256;
const BUF_SIZE: usize = 2048;

// ---------------------------------------------------------------------------
// Descriptor layouts (§3.2.3 / §3.3.3 of 82574 datasheet)
// ---------------------------------------------------------------------------
// align(16) is mandatory: the I219-V DMA engine requires all descriptors
// to be naturally aligned to 16 bytes. A second #[repr(C)] would silently
// drop the alignment, causing hard failures on real silicon.
// Legacy RX descriptor (used only for ring setup — addr field)
// The hardware writes back in *extended* format when RFCTL_EXTEN is set,
// so we never read the legacy fields; we only write the buffer address.
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug)]
struct RxDesc {
    addr:     u64,  // [63:0]  — buffer physical address (we write this)
    reserved: u64,  // [127:64] — written back by HW as ExtRxWb
}

// Extended write-back layout (RFCTL_EXTEN=1, always used on I219).
// Hardware fills this after DMA completes:
//   [31:0]  mrq / rss_type      (ignored)
//   [63:32] vlan / staterr_hi   (ignored)
//   [95:64] staterr (DD=bit0, EOP=bit1, errors in upper bytes)
//   [111:96] length (bytes in buffer)
//   [127:112] vlan tag          (ignored)
//
// In Rust memory layout (little-endian):
//   +0  u64 addr  (written by driver)
//   +8  u32 staterr   (written by HW — DD at bit 0, EOP at bit 1)
//   +12 u16 length    (written by HW)
//   +14 u16 vlan      (ignored)
#[repr(C, align(16))]
#[derive(Copy, Clone, Default)]
struct TxDesc {
    addr: u64,
    len: u16,
    cso: u8,
    cmd: u8,
    status: u8,
    css: u8,
    special: u16,
}

// ---------------------------------------------------------------------------
// DMA allocation helpers (thin wrappers over the kernel C FFI)
// ---------------------------------------------------------------------------
extern "C" {
    fn drivers_dma_alloc(pages: usize) -> usize; // returns phys addr
    fn drivers_dma_dealloc(paddr: usize, pages: usize) -> i32;
    fn drivers_phys_to_virt(paddr: usize) -> usize;
    fn drivers_virt_to_phys(vaddr: usize) -> usize;
}

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------
#[inline(always)]
unsafe fn mmio_read(base: usize, reg: usize) -> u32 {
    read_volatile((base + reg * 4) as *const u32)
}
#[inline(always)]
unsafe fn mmio_write(base: usize, reg: usize, val: u32) {
    write_volatile((base + reg * 4) as *mut u32, val);
}

// ---------------------------------------------------------------------------
// E1000eHw — raw hardware state
// ---------------------------------------------------------------------------
pub struct E1000eHw {
    base: usize, // MMIO virtual base
    pci_loc: Location,
    device_id: u16,

    mac: [u8; 6],

    rx_ring: DmaRegion,
    rx_bufs: Vec<DmaRegion>,
    rx_tail: usize,

    tx_ring: DmaRegion,
    tx_bufs: Vec<DmaRegion>,
    tx_tail: usize,
    phy_addr: u8,
    pub stats: NetStats,
    /// Last GPRC snapshot (clear-on-read); used to detect HW RX without DD.
    last_hw_rx_packets: u32,
    rx_diag_counter: u32,
}

impl E1000eHw {
    // -----------------------------------------------------------------------
    // Kumeran (KMRN) register access (ICH8/PCH specific)
    // -----------------------------------------------------------------------

    /// Busy-wait for `us` microseconds using the driver timer.
    /// `timer_now_as_micros` is imported from `super` (drivers/src/net/mod.rs).
    fn udelay(us: u64) {
        let t0 = timer_now_as_micros();
        // Hard spin guard: at most ~10M iterations (~10ms at 1GHz) regardless of
        // the requested delay. This prevents infinite loops on bare-metal when the
        // TSC-based timer hasn't started yet, without burning seconds of CPU time.
        // The guard activates only when the timer is genuinely broken; otherwise
        // the timer-based condition fires first and we exit normally.
        const MAX_SPINS: u64 = 10_000_000;
        let mut spins = 0u64;
        while timer_now_as_micros().wrapping_sub(t0) < us {
            core::hint::spin_loop();
            spins = spins.wrapping_add(1);
            if spins >= MAX_SPINS {
                warn!(
                    "[e1000e] udelay fallback hit ({}us, timer did not advance fast enough)",
                    us
                );
                break;
            }
        }
    }

    unsafe fn kmrn_read(&self, offset: u16) -> u16 {
        let cmd = ((offset as u32) << KMRNCTRLSTA_OFFSET_SHIFT) | KMRNCTRLSTA_REN;
        mmio_write(self.base, E1000E_KMRNCTRLSTA, cmd);
        let _ = mmio_read(self.base, E1000E_KMRNCTRLSTA); // flush write
        Self::udelay(2); // Linux uses udelay(2) between write and read
        (mmio_read(self.base, E1000E_KMRNCTRLSTA) & 0xFFFF) as u16
    }

    unsafe fn kmrn_write(&self, offset: u16, data: u16) {
        let cmd = ((offset as u32) << KMRNCTRLSTA_OFFSET_SHIFT) | KMRNCTRLSTA_WEN | (data as u32);
        mmio_write(self.base, E1000E_KMRNCTRLSTA, cmd);
        let _ = mmio_read(self.base, E1000E_KMRNCTRLSTA); // flush write
        Self::udelay(2); // Linux uses udelay(2) after write
    }

    // -----------------------------------------------------------------------
    // NVM word read via EERD (works on all e1000e silicon)
    // -----------------------------------------------------------------------
    unsafe fn nvm_read_word(&self, offset: u16) -> u16 {
        // Try Address Shift 2 first (82574L and most discrete e1000e)
        let cmd = ((offset as u32) << 2) | EERD_START;
        mmio_write(self.base, E1000E_EERD, cmd);
        let mut tries = (NVM_POLL_US / 50).max(1);
        while tries > 0 {
            let v = mmio_read(self.base, E1000E_EERD);
            if v & (EERD_DONE_BIT4 | EERD_DONE_BIT1) != 0 {
                return (v >> EERD_DATA_SHIFT) as u16;
            }
            Self::udelay(50); // C6: allow timer to tick on bare-metal
            tries -= 1;
        }

        // Try Address Shift 3 (PCH-integrated NICs like I217/I218/I219)
        let cmd = ((offset as u32) << 3) | EERD_START;
        mmio_write(self.base, E1000E_EERD, cmd);
        let mut tries = (NVM_POLL_US / 50).max(1);
        while tries > 0 {
            let v = mmio_read(self.base, E1000E_EERD);
            if v & (EERD_DONE_BIT4 | EERD_DONE_BIT1) != 0 {
                return (v >> EERD_DATA_SHIFT) as u16;
            }
            Self::udelay(50); // C6: allow timer to tick on bare-metal
            tries -= 1;
        }
        0
    }

    // -----------------------------------------------------------------------
    // Read MAC address from RAL0/RAH0 registers (usually set by BIOS)
    // -----------------------------------------------------------------------
    unsafe fn read_mac_from_hw(&mut self) {
        let ral = mmio_read(self.base, E1000E_RAL0);
        let rah = mmio_read(self.base, E1000E_RAH0);

        if ral == 0 && (rah & 0xFFFF) == 0 {
            return;
        }
        self.mac[0] = (ral & 0xFF) as u8;
        self.mac[1] = ((ral >> 8) & 0xFF) as u8;
        self.mac[2] = ((ral >> 16) & 0xFF) as u8;
        self.mac[3] = ((ral >> 24) & 0xFF) as u8;
        self.mac[4] = (rah & 0xFF) as u8;
        self.mac[5] = ((rah >> 8) & 0xFF) as u8;
    }

    fn is_valid_mac(&self) -> bool {
        let all_zeros = self.mac.iter().all(|&b| b == 0);
        let all_fs = self.mac.iter().all(|&b| b == 0xff);
        !all_zeros && !all_fs
    }

    /// Returns true for PCH-LPT (I217/I218) and later integrated NICs.
    fn is_pch_lpt_or_later(&self) -> bool {
        matches!(self.device_id,
            0x1502..=0x1503 | 0x153a..=0x153b | 0x155a | 0x1559 | 0x15a0..=0x15a3 |
            0x156f..=0x1570 | 0x15b7..=0x15be | 0x15d6..=0x15d8 | 0x15e3 |
            0x0d4c..=0x0d4f | 0x15f4..=0x15fc | 0x1a1c..=0x1a1f |
            0x0dc5..=0x0dc8 | 0x550a..=0x5511 | 0x57a0..=0x57a1 | 0x57b3..=0x57ba
        )
    }

    /// Returns true for PCH-SPT (I219) and later silicon.
    /// These chips require explicit RXDCTL/TXDCTL QUEUE_ENABLE (bit 25) to
    /// activate the RX/TX DMA queues after RCTL_EN/TCTL_EN.
    fn is_pch_spt_or_later(&self) -> bool {
        matches!(self.device_id,
            0x156f..=0x1570 | 0x15b7..=0x15be | 0x15d6..=0x15d8 | 0x15e3 |
            0x0d4c..=0x0d4f | 0x15f4..=0x15fc | 0x1a1c..=0x1a1f |
            0x0dc5..=0x0dc8 | 0x550a..=0x5511 | 0x57a0..=0x57a1 | 0x57b3..=0x57ba |
            0x15df..=0x15e2 | 0x0d53 | 0x0d55 | 0x15f9 | 0x15fa
        )
    }


    // -----------------------------------------------------------------------
    // Read MAC address from NVM (3 words at offsets 0, 1, 2)
    // -----------------------------------------------------------------------
    unsafe fn read_mac_from_nvm(&mut self) {
        let w0 = self.nvm_read_word(0);
        let w1 = self.nvm_read_word(1);
        let w2 = self.nvm_read_word(2);
        self.mac[0] = (w0 & 0xFF) as u8;
        self.mac[1] = (w0 >> 8) as u8;
        self.mac[2] = (w1 & 0xFF) as u8;
        self.mac[3] = (w1 >> 8) as u8;
        self.mac[4] = (w2 & 0xFF) as u8;
        self.mac[5] = (w2 >> 8) as u8;
        info!(
            "[e1000e] MAC from NVM: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.mac[0], self.mac[1], self.mac[2], self.mac[3], self.mac[4], self.mac[5]
        );
    }

    unsafe fn toggle_lanphypc(&self) {
        if !self.is_pch_lpt_or_later() {
            return;
        }
        let mut fextnvm3 = mmio_read(self.base, E1000E_FEXTNVM3);
        fextnvm3 &= !0x3F; // PHY_CFG_COUNTER_MASK
        fextnvm3 |= 0x20; // 50 msec counter
        mmio_write(self.base, E1000E_FEXTNVM3, fextnvm3);
        let _ = mmio_read(self.base, E1000E_FEXTNVM3); // flush posted write (M8)

        // Phase 1: assert OVERRIDE, deassert VALUE (drive LANPHYPC low)
        let mut ctrl = mmio_read(self.base, E1000E_CTRL);
        ctrl |= CTRL_LANPHYPC_OVERRIDE;
        ctrl &= !CTRL_LANPHYPC_VALUE;
        mmio_write(self.base, E1000E_CTRL, ctrl);
        let _ = mmio_read(self.base, E1000E_CTRL); // flush posted write
        Self::udelay(20);

        // Phase 2: deassert OVERRIDE (release LANPHYPC back to hardware control).
        // Re-read CTRL here so we don't accidentally clear bits that were set
        // by the PCH between phase 1 and phase 2 (e.g. GIO_MASTER state).
        ctrl = mmio_read(self.base, E1000E_CTRL);
        ctrl &= !CTRL_LANPHYPC_OVERRIDE;
        mmio_write(self.base, E1000E_CTRL, ctrl);
        let _ = mmio_read(self.base, E1000E_CTRL); // flush
        // Give the PHY time to power up after LANPHYPC deassert
        Self::udelay(50_000); // 50 ms, matches Linux e1000_toggle_lanphypc_via_cmdc
    }

    unsafe fn disable_ulp(&self) {
        if !self.is_pch_lpt_or_later() {
            return;
        }
        
        let fwsm = mmio_read(self.base, E1000E_FWSM);
        if fwsm & 0x8000 != 0 {
            // E1000_ICH_FWSM_FW_VALID is set: Intel ME firmware is active.
            warn!("[e1000e] Intel ME firmware active (FWSM={:#010x})", fwsm);
        }

        // Linux e1000_disable_ulp_lpt_lp: clear ULP enable and indicator bits in H2ME.
        // H2ME = 0x05B50. Bit 11 is ULP_INDICATOR, Bit 10 is ULP_EN.
        // We also check for START/DONE bits if we want to be very safe, but clearing
        // these bits is generally safe even if ME is active, as long as we don't
        // trigger a new request that the ME isn't ready for.
        let mut h2me = mmio_read(self.base, E1000E_H2ME);
        if h2me & ((1 << 11) | (1 << 10)) != 0 {
            warn!("[e1000e] ULP active in H2ME ({:#x}), disabling...", h2me);
            h2me &= !((1 << 11) | (1 << 10));
            mmio_write(self.base, E1000E_H2ME, h2me);
            let _ = mmio_read(self.base, E1000E_H2ME); // flush
            Self::udelay(100);
        }
    }

    // -----------------------------------------------------------------------
    // Flush descriptor rings (I219 workaround)
    // -----------------------------------------------------------------------
    unsafe fn flush_desc_rings(&self) {
        // Only SPT (I219) and later require this.
        if !self.is_pch_spt_or_later() {
            return;
        }

        // Check if flush is required via PCI config space.
        let hang_state = PCI_ACCESS.read16(&PortOpsImpl, self.pci_loc, PCICFG_DESC_RING_STATUS);
        if (hang_state & FLUSH_DESC_REQUIRED) == 0 {
            return;
        }

        warn!("[e1000e] I219 pre-reset flush (state={:#x}): setting FEXTNVM bits only", hang_state);

        // SAFE path: only write FEXTNVM7/FEXTNVM11 status bits.
        // DO NOT enable TX/RX DMA here — the NIC is still in its BIOS-handed
        // state and activating the DMA engine before CTRL_RST can trigger a
        // PCIe fatal error (completion timeout / unsupported request) that
        // freezes the entire system, requiring a power cycle to recover.
        // The hardware reset (CTRL_RST, issued next) will clear the ring-hang
        // condition without needing us to pump dummy descriptors through DMA.
        let mut fextnvm7 = mmio_read(self.base, E1000E_FEXTNVM7);
        fextnvm7 |= FEXTNVM7_NEED_DESCR_RING_FLUSH;
        mmio_write(self.base, E1000E_FEXTNVM7, fextnvm7);
        let _ = mmio_read(self.base, E1000E_FEXTNVM7); // flush posted write

        let mut fextnvm11 = mmio_read(self.base, E1000E_FEXTNVM11);
        fextnvm11 |= FEXTNVM11_DISABLE_MULR_FIX;
        mmio_write(self.base, E1000E_FEXTNVM11, fextnvm11);
        let _ = mmio_read(self.base, E1000E_FEXTNVM11); // flush posted write
    }

    /// Push CPU-written DMA data to RAM for the device (WB cache).
    /// Use only on CPU→device paths (TX buffers, descriptor recycle). Never call
    /// before reading device write-back (RX descriptor DD, RX payload, TX DD).
    unsafe fn dma_wbinv_range(vaddr: usize, len: usize) {
        if len == 0 {
            return;
        }
        let mut p = vaddr & !63;
        let end = vaddr.saturating_add(len);
        while p < end {
            core::arch::x86_64::_mm_clflush(p as *const u8);
            p += 64;
        }
        fence(Ordering::SeqCst);
    }

    /// Invalidate CPU cache for a descriptor line before reading device write-back.
    unsafe fn dma_inv_desc(desc_addr: usize) {
        core::arch::x86_64::_mm_clflush(desc_addr as *const u8);
        fence(Ordering::SeqCst);
    }

    /// Read a range the device wrote into WB memory. Never clflush here: on x86
    /// CLFLUSH writebacks dirty cache lines and destroys device-written data.
    unsafe fn dma_copy_in(dst: &mut Vec<u8>, vaddr: usize, len: usize) {
        dst.clear();
        dst.reserve(len);
        for i in 0..len {
            dst.push(core::ptr::read_volatile((vaddr + i) as *const u8));
        }
    }

    unsafe fn stop_rx_tx_engines(&self) {
        let rctl = mmio_read(self.base, E1000E_RCTL);
        mmio_write(self.base, E1000E_RCTL, rctl & !RCTL_EN);
        let tctl = mmio_read(self.base, E1000E_TCTL);
        mmio_write(self.base, E1000E_TCTL, tctl & !TCTL_EN);
        Self::udelay(100);
    }

    /// Linux `e1000_acquire_swflag_ich8lan`: software PHY/MDIO ownership.
    unsafe fn pch_swflag_acquire(&self) -> bool {
        for _ in 0..200 {
            let v = mmio_read(self.base, E1000E_EXTCNF_CTRL);
            if v & EXTCNF_CTRL_SWFLAG == 0 {
                break;
            }
            Self::udelay(1_000);
        }
        let mut v = mmio_read(self.base, E1000E_EXTCNF_CTRL);
        if v & EXTCNF_CTRL_SWFLAG != 0 {
            warn!("[e1000e] EXTCNF_CTRL SWFLAG held by FW/HW");
            return false;
        }
        v |= EXTCNF_CTRL_SWFLAG;
        mmio_write(self.base, E1000E_EXTCNF_CTRL, v);
        for _ in 0..200 {
            let r = mmio_read(self.base, E1000E_EXTCNF_CTRL);
            if r & EXTCNF_CTRL_SWFLAG != 0 {
                return true;
            }
            Self::udelay(1_000);
        }
        warn!("[e1000e] failed to set EXTCNF_CTRL SWFLAG");
        let r = mmio_read(self.base, E1000E_EXTCNF_CTRL);
        mmio_write(
            self.base,
            E1000E_EXTCNF_CTRL,
            r & !EXTCNF_CTRL_SWFLAG,
        );
        false
    }

    unsafe fn pch_swflag_release(&self) {
        let mut v = mmio_read(self.base, E1000E_EXTCNF_CTRL);
        if v & EXTCNF_CTRL_SWFLAG != 0 {
            v &= !EXTCNF_CTRL_SWFLAG;
            mmio_write(self.base, E1000E_EXTCNF_CTRL, v);
            let _ = mmio_read(self.base, E1000E_EXTCNF_CTRL);
        }
    }

    /// Linux `e1000_get_cfg_done_ich8lan` / `e1000_lan_init_done_ich8lan` after PHY_RST.
    unsafe fn pch_phy_reset_complete(&self) {
        Self::udelay(10_000);
        let mut loops = 1500u32;
        while loops > 0 {
            let s = mmio_read(self.base, E1000E_STATUS);
            if s & STATUS_LAN_INIT_DONE != 0 {
                break;
            }
            Self::udelay(150);
            loops -= 1;
        }
        if loops == 0 {
            warn!("[e1000e] STATUS.LAN_INIT_DONE timeout after PHY_RST");
        }
        let mut s = mmio_read(self.base, E1000E_STATUS);
        if s & STATUS_LAN_INIT_DONE != 0 {
            mmio_write(
                self.base,
                E1000E_STATUS,
                s & !STATUS_LAN_INIT_DONE,
            );
            let _ = mmio_read(self.base, E1000E_STATUS);
        }
        s = mmio_read(self.base, E1000E_STATUS);
        if s & STATUS_PHYRA != 0 {
            mmio_write(
                self.base,
                E1000E_STATUS,
                s & !STATUS_PHYRA,
            );
            let _ = mmio_read(self.base, E1000E_STATUS);
        }
    }

    unsafe fn pch_issue_phy_reset(&self) {
        let ext_saved = mmio_read(self.base, E1000E_EXTCNF_CTRL);
        mmio_write(
            self.base,
            E1000E_EXTCNF_CTRL,
            ext_saved | EXTCNF_CTRL_GATE_PHY_CFG,
        );
        let _ = mmio_read(self.base, E1000E_EXTCNF_CTRL);

        if !self.pch_swflag_acquire() {
            mmio_write(self.base, E1000E_EXTCNF_CTRL, ext_saved);
            warn!("[e1000e] PCH: PHY_RST skipped (no SWFLAG)");
            return;
        }

        let ctrl = mmio_read(self.base, E1000E_CTRL);
        mmio_write(self.base, E1000E_CTRL, ctrl | CTRL_PHY_RST);
        let _ = mmio_read(self.base, E1000E_CTRL);
        Self::udelay(100);
        mmio_write(self.base, E1000E_CTRL, ctrl);
        let _ = mmio_read(self.base, E1000E_CTRL);
        Self::udelay(300);

        self.pch_phy_reset_complete();

        self.pch_swflag_release();

        let ext = mmio_read(self.base, E1000E_EXTCNF_CTRL);
        mmio_write(
            self.base,
            E1000E_EXTCNF_CTRL,
            ext & !EXTCNF_CTRL_GATE_PHY_CFG,
        );
        let _ = mmio_read(self.base, E1000E_EXTCNF_CTRL);
    }

    /// Clear STATUS.PHYRA if set (Linux `e1000_get_cfg_done_ich8lan`). Safe when
    /// PHY_RST was skipped because firmware may leave this bit asserted.
    unsafe fn pch_clear_status_phyra_if_set(&self) {
        let s = mmio_read(self.base, E1000E_STATUS);
        if s & STATUS_PHYRA != 0 {
            warn!("[e1000e] clearing STATUS.PHYRA (status was {:#x})", s);
            mmio_write(self.base, E1000E_STATUS, s & !STATUS_PHYRA);
            let _ = mmio_read(self.base, E1000E_STATUS);
        }
    }

    unsafe fn mdic_read(&self, phy_addr: u8, reg: u32) -> Option<u16> {
        let is_pch = self.is_pch_lpt_or_later();
        if is_pch && !self.pch_swflag_acquire() {
            return None;
        }

        let cmd =
            (reg << MDIC_REG_SHIFT) | ((phy_addr as u32) << MDIC_PHY_SHIFT) | MDIC_OP_READ;
        mmio_write(self.base, E1000E_MDIC, cmd);
        let mut res = None;
        for _ in 0..400 {
            Self::udelay(50);
            let mdic = mmio_read(self.base, E1000E_MDIC);
            if mdic & MDIC_READY != 0 {
                if mdic & MDIC_ERROR == 0 {
                    res = Some((mdic & 0xFFFF) as u16);
                }
                break;
            }
        }

        if is_pch {
            self.pch_swflag_release();
        }
        res
    }

    /// Paged PHY access (Linux `__e1000e_read_phy_reg_igp`).
    unsafe fn mdic_read_phy(&self, phy_addr: u8, offset: u32) -> Option<u16> {
        if offset > MAX_PHY_MULTI_PAGE_REG {
            if !self.mdic_write(phy_addr, IGP_PHY_PAGE_SELECT, offset as u16) {
                return None;
            }
        }
        self.mdic_read(phy_addr, offset & 0x1F)
    }

    unsafe fn mdic_write_phy(&self, phy_addr: u8, offset: u32, val: u16) -> bool {
        if offset > MAX_PHY_MULTI_PAGE_REG {
            if !self.mdic_write(phy_addr, IGP_PHY_PAGE_SELECT, offset as u16) {
                return false;
            }
        }
        self.mdic_write(phy_addr, offset & 0x1F, val)
    }

    unsafe fn mdic_write(&self, phy_addr: u8, reg: u32, val: u16) -> bool {
        let is_pch = self.is_pch_lpt_or_later();
        if is_pch && !self.pch_swflag_acquire() {
            return false;
        }

        let cmd = (val as u32)
            | (reg << MDIC_REG_SHIFT)
            | ((phy_addr as u32) << MDIC_PHY_SHIFT)
            | MDIC_OP_WRITE;
        mmio_write(self.base, E1000E_MDIC, cmd);
        let mut ok = false;
        for _ in 0..400 {
            Self::udelay(50);
            let mdic = mmio_read(self.base, E1000E_MDIC);
            if mdic & MDIC_READY != 0 {
                ok = (mdic & MDIC_ERROR) == 0;
                break;
            }
        }

        if is_pch {
            self.pch_swflag_release();
        }
        ok
    }

    unsafe fn phy_bmsr_link_up(&self, phy_addr: u8) -> bool {
        self.mdic_read(phy_addr, MII_BMSR)
            .map(|b| b != 0 && b != 0xFFFF && (b & 0x0004) != 0)
            .unwrap_or(false)
    }

    /// Speed/duplex from cached PHY reg 26 (Linux I82577_PHY_STATUS_2 one-hot 0x300).
    fn phy_resolve_speed_duplex_st2(st2: u16) -> Option<(u32, u32)> {
        if st2 == 0 || st2 == 0xFFFF {
            return None;
        }
        let bits = st2 & PHY_STATUS2_SPEED_MASK;
        if bits == PHY_STATUS2_SPEED_1000 {
            return Some((2, 1));
        }
        if bits == PHY_STATUS2_SPEED_100 {
            return Some((1, 1));
        }
        if bits == 0 {
            return Some((0, 1));
        }
        None
    }

    /// Speed/duplex from PHY reg 26, then PSS reg 17, else 1000/full.
    unsafe fn phy_resolve_speed_duplex(&self, phy_addr: u8) -> (u32, u32) {
        for _ in 0..3 {
            if let Some(st2) = self.mdic_read(phy_addr, MII_PHY_STATUS_2) {
                if let Some(sd) = Self::phy_resolve_speed_duplex_st2(st2) {
                    return sd;
                }
            }
            Self::udelay(200);
        }
        let _ = self.mdic_read(phy_addr, 17);
        Self::udelay(500);
        if let Some(pss) = self.mdic_read(phy_addr, 17) {
            if pss != 0 && pss != 0xFFFF {
                return (((pss >> 14) & 0x3) as u32, ((pss >> 13) & 0x1) as u32);
            }
        }
        (2, 1)
    }

    /// Brief FRCSPD+SPD_BYPS pulse then restore (Linux `e1000_configure_k1_ich8lan`).
    unsafe fn mac_speed_sync_pulse(&self) {
        let ctrl_ext = mmio_read(self.base, E1000E_CTRL_EXT);
        let ctrl_saved = mmio_read(self.base, E1000E_CTRL);
        let mut pulse = ctrl_saved & !(CTRL_SPD_1000 | CTRL_SPD_100);
        pulse |= CTRL_FRCSPD;
        mmio_write(self.base, E1000E_CTRL, pulse);
        mmio_write(self.base, E1000E_CTRL_EXT, ctrl_ext | CTRL_EXT_SPD_BYPS);
        Self::udelay(40);
        mmio_write(self.base, E1000E_CTRL, ctrl_saved);
        mmio_write(self.base, E1000E_CTRL_EXT, ctrl_ext);
        let _ = mmio_read(self.base, E1000E_CTRL);
    }

    fn phy_speed_label(speed: u32) -> &'static str {
        match speed {
            2 => "1000",
            1 => "100",
            _ => "10",
        }
    }

    #[inline]
    fn phy_reg_paged(page: u32, reg: u32) -> u32 {
        (page << 5) | reg
    }

    /// Linux `e1000e_get_speed_and_duplex_copper` (STATUS bits 6:7 + FD).
    fn speed_mbps_from_status(status: u32) -> u32 {
        if status & STATUS_SPEED_1000 != 0 {
            SPEED_1000
        } else if status & STATUS_SPEED_100 != 0 {
            SPEED_100
        } else {
            SPEED_10
        }
    }

    fn speed_idx_from_status(status: u32) -> u32 {
        if status & STATUS_SPEED_1000 != 0 {
            2
        } else if status & STATUS_SPEED_100 != 0 {
            1
        } else {
            0
        }
    }

    unsafe fn active_phy_addr(&self) -> u8 {
        for pa in [self.phy_addr, 1u8, 2u8] {
            if self.phy_bmsr_link_up(pa) {
                return pa;
            }
        }
        self.phy_addr
    }

    /// Set negotiated speed in CTRL from PHY reg 26 — no FRCSPD (safe on I219 RX).
    unsafe fn mac_sync_ctrl_speed_from_st2(&self, st2: u16) -> bool {
        let Some((speed, duplex)) = Self::phy_resolve_speed_duplex_st2(st2) else {
            return false;
        };
        let mut ctrl = mmio_read(self.base, E1000E_CTRL);
        ctrl &= !(CTRL_FRCSPD | CTRL_FRCDPX | CTRL_SPD_1000 | CTRL_SPD_100);
        ctrl |= CTRL_SLU | CTRL_ASDE;
        if speed == 2 {
            ctrl |= CTRL_SPD_1000;
        } else if speed == 1 {
            ctrl |= CTRL_SPD_100;
        }
        if duplex != 0 {
            ctrl |= CTRL_FD;
        }
        mmio_write(self.base, E1000E_CTRL, ctrl);
        let _ = mmio_read(self.base, E1000E_CTRL);
        crate::klog_info!(
            "[e1000e] CTRL speed from reg26={:#x} -> {} Mb/s CTRL={:#x}\n",
            st2,
            Self::phy_speed_label(speed),
            ctrl
        );
        true
    }

    /// Linux `e1000_check_for_copper_link_ich8lan` TIPG + I217_RX_CONFIG EMI + PLL gate.
    unsafe fn program_link_tipg_emi_linux(&self, phy_addr: u8) {
        if !self.is_pch_lpt_or_later() {
            return;
        }
        let status = mmio_read(self.base, E1000E_STATUS);
        let speed = Self::speed_mbps_from_status(status);
        let duplex_full = status & STATUS_FD != 0;

        let mut tipg = mmio_read(self.base, E1000E_TIPG);
        tipg &= !0x3FF;
        let emi_val = if !duplex_full && speed == SPEED_10 {
            tipg |= 0xFF;
            0u16
        } else if self.is_pch_spt_or_later() && duplex_full && speed != SPEED_1000 {
            tipg |= 0x0C;
            1u16
        } else {
            tipg |= 0x08;
            1u16
        };
        mmio_write(self.base, E1000E_TIPG, tipg);

        if !self.phy_write_emi(phy_addr, I217_RX_CONFIG_EMI, emi_val) {
            crate::klog_warn!(
                "[e1000e] I217_RX_CONFIG EMI={} failed PHY{}\n",
                emi_val,
                phy_addr
            );
        }

        if self.is_pch_lpt_or_later() {
            let pll_reg = Self::phy_reg_paged(772, 28);
            if let Some(mut phy_reg) = self.mdic_read_phy(phy_addr, pll_reg) {
                phy_reg &= !I217_PLL_CLOCK_GATE_MASK;
                if speed == SPEED_100 || speed == SPEED_10 {
                    phy_reg |= 0x3E8;
                } else {
                    phy_reg |= 0xFA;
                }
                let _ = self.mdic_write_phy(phy_addr, pll_reg, phy_reg);
            }
        }
    }

    /// Linux `e1000e_set_pcie_no_snoop` for PCH2+ (clear GCR no-snoop bits).
    unsafe fn pch_setup_pcie_no_snoop(&self) {
        if !self.is_pch_lpt_or_later() {
            return;
        }
        let mut gcr = mmio_read(self.base, E1000E_GCR);
        gcr &= !GCR_PCIE_NO_SNOOP_ALL;
        mmio_write(self.base, E1000E_GCR, gcr);
        let _ = mmio_read(self.base, E1000E_GCR);
    }

    /// Linux `e1000_setup_copper_link_ich8lan` KMRN + inband parameters.
    unsafe fn pch_setup_kmrn_copper_link(&self) {
        self.kmrn_write(KMRNCTRLSTA_TIMEOUTS, 0xFFFF);
        let mut inband = self.kmrn_read(KMRNCTRLSTA_INBAND_PARAM);
        inband |= 0x3F;
        self.kmrn_write(KMRNCTRLSTA_INBAND_PARAM, inband);
    }

    /// Linux `e1000_setup_copper_link_ich8lan`: SLU, clear FRCSPD/FRCDPX only.
    unsafe fn mac_setup_copper_link_linux(&self) {
        let mut ctrl = mmio_read(self.base, E1000E_CTRL);
        ctrl |= CTRL_SLU | CTRL_ASDE | CTRL_FD;
        ctrl &= !(CTRL_FRCSPD | CTRL_FRCDPX);
        mmio_write(self.base, E1000E_CTRL, ctrl);
        let _ = mmio_read(self.base, E1000E_CTRL);
    }

    /// ASDE sync from PHY reg26 only when STATUS speed disagrees (I219 metal).
    unsafe fn mac_reconcile_phy_speed(&self, phy_addr: u8, st2: u16) {
        self.mac_setup_copper_link_linux();
        let status = mmio_read(self.base, E1000E_STATUS);
        let st_idx = Self::phy_resolve_speed_duplex_st2(st2).map(|(s, _)| s);
        let mac_idx = Self::speed_idx_from_status(status);
        if let Some(phy_idx) = st_idx {
            if phy_idx != mac_idx {
                crate::klog_warn!(
                    "[e1000e] STATUS spd idx {} != PHY reg26={:#x} idx {} — sync CTRL\n",
                    mac_idx,
                    st2,
                    phy_idx
                );
                let _ = self.mac_sync_ctrl_speed_from_st2(st2);
            }
        }
    }

    /// Post-link path without resetting RX rings (Linux LSC / watchdog).
    unsafe fn apply_link_adjustments_linux(&self) {
        if mmio_read(self.base, E1000E_STATUS) & STATUS_LU == 0 {
            return;
        }
        self.disable_ulp();
        let phy = self.active_phy_addr();
        let st2 = self.pch_post_link_phy_tune();
        self.mac_reconcile_phy_speed(phy, st2);
        self.program_link_tipg_emi_linux(phy);
    }

    unsafe fn pch_disable_k1(&self) {
        let mut kmrn = self.kmrn_read(KMRNCTRLSTA_K1_CONFIG);
        kmrn &= !KMRNCTRLSTA_K1_ENABLE;
        self.kmrn_write(KMRNCTRLSTA_K1_CONFIG, kmrn);
    }

    /// Alias kept for call sites — matches Linux copper link CTRL programming.
    unsafe fn mac_allow_autoneg(&self) {
        self.mac_setup_copper_link_linux();
    }

    unsafe fn pulse_slu(&self) {
        let mut ctrl = mmio_read(self.base, E1000E_CTRL);
        ctrl &= !CTRL_SLU;
        mmio_write(self.base, E1000E_CTRL, ctrl);
        let _ = mmio_read(self.base, E1000E_CTRL);
        Self::udelay(10_000);
        ctrl |= CTRL_SLU;
        mmio_write(self.base, E1000E_CTRL, ctrl);
        let _ = mmio_read(self.base, E1000E_CTRL);
    }

    /// PHY reports link (BMSR) but MAC `STATUS.LU` is 0 — common on I219 after no MAC reset.
    unsafe fn pch_sync_mac_from_phy(&mut self) -> bool {
        for phy_addr in [self.phy_addr, 1u8, 2u8] {
            if !self.phy_bmsr_link_up(phy_addr) {
                continue;
            }
            self.phy_addr = phy_addr;
            let st2 = self.mdic_read(phy_addr, MII_PHY_STATUS_2).unwrap_or(0);
            crate::klog_warn!("[e1000e] MAC/PHY desync: PHY{} up but STATUS.LU=0, re-autoneg\n", phy_addr);
            self.mac_allow_autoneg();
            self.pch_kick_autoneg_mdio();
            for pulse in 0..3u32 {
                for _ in 0..20 {
                    Self::udelay(50_000);
                    if mmio_read(self.base, E1000E_STATUS) & STATUS_LU != 0 {
                        self.mac_allow_autoneg();
                        crate::klog_info!("[e1000e] MAC/PHY sync OK\n");
                        return true;
                    }
                }
                if pulse < 2 {
                    self.pulse_slu();
                }
            }
        }
        false
    }

    /// Clause-22 BMCR autoneg restart (PHY addr 1 or 2, per Linux PCH probe).
    unsafe fn pch_kick_autoneg_mdio(&self) {
        // MDIO operations now handle SWFLAG themselves.
        let mut did = false;
        for phy_addr in [1u8, 2u8] {
            if let Some(bmcr) = self.mdic_read(phy_addr, MII_BMCR) {
                if bmcr == 0 || bmcr == 0xFFFF {
                    continue;
                }
                if let Some(anar) = self.mdic_read(phy_addr, MII_ADVERTISE) {
                    if anar != 0 && anar != 0xFFFF {
                        let new_anar = anar | ADVERTISE_ALL_COPPER;
                        if new_anar != anar {
                            let _ = self.mdic_write(phy_addr, MII_ADVERTISE, new_anar);

                        }
                    }
                }
                if let Some(ctrl1000) = self.mdic_read(phy_addr, MII_CTRL1000) {
                    if ctrl1000 != 0 && ctrl1000 != 0xFFFF {
                        let new_ctrl1000 = ctrl1000 | ADVERTISE_1000FULL;
                        if new_ctrl1000 != ctrl1000 {
                            let _ = self.mdic_write(phy_addr, MII_CTRL1000, new_ctrl1000);

                        }
                    }
                }
                let new_bmcr = bmcr | BMCR_ANENABLE | BMCR_ANRESTART;
                let _ = self.mdic_write(phy_addr, MII_BMCR, new_bmcr);
                did = true;
                break;
            }
        }
        if !did {
            crate::klog_warn!("[e1000e] MDIO: no PHY responding on addr 1 or 2\n");
        }
    }

    /// Linux `e1000_init_hw_ich8lan` / link workarounds needed on I217/I219 real silicon.
    unsafe fn pch_apply_silicon_workarounds(&self) {
        let mut rfctl = mmio_read(self.base, E1000E_RFCTL);
        rfctl |= RFCTL_NFSW_DIS | RFCTL_NFSR_DIS | RFCTL_IPV6_EX_DIS | RFCTL_NEW_IPV6_EXT_DIS;
        mmio_write(self.base, E1000E_RFCTL, rfctl);

        let mut pbeccsts = mmio_read(self.base, E1000E_PBECCSTS);
        pbeccsts |= PBECCSTS_ECC_ENABLE;
        mmio_write(self.base, E1000E_PBECCSTS, pbeccsts);

        let mut ctrl = mmio_read(self.base, E1000E_CTRL);
        ctrl |= CTRL_MEHE;
        mmio_write(self.base, E1000E_CTRL, ctrl);

        // I217/I219 packet-loss fix (Linux e1000_setup_link_ich8lan).
        let mut fextnvm4 = mmio_read(self.base, E1000E_FEXTNVM4);
        fextnvm4 &= !FEXTNVM4_BEACON_DURATION_MASK;
        fextnvm4 |= FEXTNVM4_BEACON_DURATION_8USEC;
        mmio_write(self.base, E1000E_FEXTNVM4, fextnvm4);

        let mut fextnvm7 = mmio_read(self.base, E1000E_FEXTNVM7);
        fextnvm7 |= FEXTNVM7_SIDE_CLK_UNGATE | FEXTNVM7_DISABLE_SMB_PERST;
        mmio_write(self.base, E1000E_FEXTNVM7, fextnvm7);

        let mut fextnvm11 = mmio_read(self.base, E1000E_FEXTNVM11);
        fextnvm11 |= FEXTNVM11_DISABLE_L1_2 | FEXTNVM11_DISABLE_MULR_FIX;
        mmio_write(self.base, E1000E_FEXTNVM11, fextnvm11);

        self.kmrn_write(KMRNCTRLSTA_TIMEOUTS, 0xFFFF);

        self.pch_setup_pcie_no_snoop();
        let mut ctrl_ext = mmio_read(self.base, E1000E_CTRL_EXT);
        ctrl_ext |= CTRL_EXT_RO_DIS;
        mmio_write(self.base, E1000E_CTRL_EXT, ctrl_ext);

        // TXDCTL bit 22 (Linux initialize_hw_bits_ich8lan).
        for txdctl_reg in [E1000E_TXDCTL, E1000E_TXDCTL1] {
            let mut txdctl = mmio_read(self.base, txdctl_reg);
            txdctl |= 1 << 22;
            mmio_write(self.base, txdctl_reg, txdctl);
        }
    }

    unsafe fn program_rxdctl(&self) {
        let mut rxdctl = mmio_read(self.base, E1000E_RXDCTL);
        rxdctl &= 0xffff_c000;
        rxdctl |= RXDCTL_DMA_BURST;
        if self.is_pch_spt_or_later() {
            rxdctl |= RXDCTL_QUEUE_ENABLE;
        }
        mmio_write(self.base, E1000E_RXDCTL, rxdctl);
        if self.is_pch_spt_or_later() {
            let mut rxq_wait = 100;
            while rxq_wait > 0 && mmio_read(self.base, E1000E_RXDCTL) & RXDCTL_QUEUE_ENABLE == 0 {
                Self::udelay(100);
                rxq_wait -= 1;
            }
        }
    }

    unsafe fn rctl_rx_bits(&self) -> u32 {
        let mut rctl = mmio_read(self.base, E1000E_RCTL);
        rctl &= !RCTL_MO_MASK;
        // Linux e1000_setup_rctl: EN | BAM | SECRC, 2048-byte buffers, no promisc.
        rctl |= RCTL_EN | RCTL_BAM | RCTL_SECRC;
        rctl &= !(RCTL_SBP | RCTL_LPE | RCTL_DTYP_PS | RCTL_BSEX | RCTL_RX_SZ_MASK | RCTL_UPE | RCTL_MPE);
        rctl
    }

    /// Linux `e1000_flush_rx_ring`: apply RXDCTL threshold changes safely.
    unsafe fn flush_rx_ring_toggle(&self) {
        let rctl_saved = mmio_read(self.base, E1000E_RCTL);
        mmio_write(self.base, E1000E_RCTL, rctl_saved & !RCTL_EN);
        Self::udelay(150);
        self.program_rxdctl();
        mmio_write(self.base, E1000E_RCTL, rctl_saved | RCTL_EN);
        Self::udelay(150);
        mmio_write(self.base, E1000E_RCTL, rctl_saved & !RCTL_EN);
        Self::udelay(100);
    }

    unsafe fn log_rx_path_regs(&self, tag: &str) {
        let ctrl = mmio_read(self.base, E1000E_CTRL);
        let status = mmio_read(self.base, E1000E_STATUS);
        let frc = (ctrl & (CTRL_FRCSPD | CTRL_FRCDPX)) != 0;
        let mac_spd = if ctrl & CTRL_SPD_1000 != 0 {
            "1000"
        } else if ctrl & CTRL_SPD_100 != 0 {
            "100"
        } else {
            "10"
        };
        crate::klog_info!(
            "e1000e: {} CTRL={:#x} mac_spd={} FRC={} STATUS={:#x} RCTL={:#x} GPRC={} RDH={} RDT={}\n",
            tag,
            ctrl,
            mac_spd,
            if frc { "BAD" } else { "ok" },
            status,
            mmio_read(self.base, E1000E_RCTL),
            mmio_read(self.base, E1000E_GPRC),
            mmio_read(self.base, E1000E_RDH),
            mmio_read(self.base, E1000E_RDT)
        );
    }

    unsafe fn wait_for_speed_status(&self, max_ms: u32) -> u32 {
        let steps = (max_ms as u64 * 1000 / 50).max(1);
        for _ in 0..steps {
            let status = mmio_read(self.base, E1000E_STATUS);
            if status & STATUS_LU != 0 {
                // SPEED_MASK == 0 is valid: it means 10 Mb/s (bits[7:6] = 00).
                // Only keep waiting if STATUS.LU itself is not yet set.
                return status;
            }
            Self::udelay(50);
        }
        mmio_read(self.base, E1000E_STATUS)
    }

    unsafe fn phy_write_emi(&self, phy_addr: u8, emi_addr: u16, data: u16) -> bool {
        self.mdic_write(phy_addr, PHY_EMI_ADDR, emi_addr)
            && self.mdic_write(phy_addr, PHY_EMI_DATA, data)
    }

    /// Linux `e1000_setup_copper_link_ich8lan` + post-link RX PHY tuning (I217/I219).
    /// Returns PHY reg 26 read before MDIO tuning writes (used for MAC speed).
    unsafe fn pch_post_link_phy_tune(&self) -> u16 {
        self.kmrn_write(KMRNCTRLSTA_TIMEOUTS, 0xFFFF);
        self.pch_disable_k1();

        let phy = self.active_phy_addr();
        let st2_cached = self.mdic_read(phy, MII_PHY_STATUS_2).unwrap_or(0);
        if let Some(mut cfg) = self.mdic_read(phy, I82577_CFG_REG) {
            if cfg != 0 && cfg != 0xFFFF {
                cfg |= I82577_CFG_ASSERT_CRS_ON_TX | I82577_CFG_ENABLE_DOWNSHIFT;
                let _ = self.mdic_write(phy, I82577_CFG_REG, cfg);
            }
        }

        if !self.mdic_write_phy(phy, PHY_REG_770_19, 0x0100) {
            crate::klog_warn!("[e1000e] link-stall PHY reg write failed\n");
        }

        let st2_after = self.mdic_read(phy, MII_PHY_STATUS_2).unwrap_or(0);
        // Post-tune read reflects negotiated speed; pre-tune can be stale (10M).
        let st2 = if st2_after != 0 && st2_after != 0xFFFF {
            st2_after
        } else {
            st2_cached
        };
        let (speed, _) = Self::phy_resolve_speed_duplex_st2(st2)
            .unwrap_or_else(|| self.phy_resolve_speed_duplex(phy));
        crate::klog_info!(
            "[e1000e] post-link PHY{} reg26={:#x} cached={:#x} phy_speed={}\n",
            phy,
            st2,
            st2_cached,
            Self::phy_speed_label(speed)
        );

        st2
    }

    /// Arm RX rings and enable RCTL — call only when STATUS.LU is set.
    unsafe fn enable_rx_after_link(&mut self) {
        let _ = self.wait_for_speed_status(3000);
        self.apply_link_adjustments_linux();

        let status = mmio_read(self.base, E1000E_STATUS);
        let spd = Self::speed_mbps_from_status(status);
        crate::klog_info!(
            "[e1000e] RX enabled: {} Mb/s STATUS={:#x}\n",
            spd,
            status
        );

        // 1. Re-arm RFCTL before touching the ring so extended WB is active.
        let mut rfctl = mmio_read(self.base, E1000E_RFCTL);
        rfctl |= RFCTL_EXTEN | RFCTL_NFSW_DIS | RFCTL_NFSR_DIS;
        mmio_write(self.base, E1000E_RFCTL, rfctl);

        // SRRCTL: 2 KB buffer size + Drop_Enable (bit 31).
        // Drop_En prevents RX ring overflow from stalling the TX path on I219.
        mmio_write(self.base, E1000E_SRRCTL, 2 | (1 << 31));

        // 2. Stop RCTL_EN, flush pending DMA, reprogram RXDCTL.
        self.flush_rx_ring_toggle();
        self.program_rxdctl();

        // 3. Re-initialise descriptors (clears all stale write-back regions)
        //    and reset our software tail pointer.
        self.reinit_rx_ring(); // sets rx_tail = 0

        // 4. Reset the ring head, arm RCTL_EN, and tell hardware where the
        //    last valid descriptor is.  RDH=0, RDT=NUM_RX-1 means all 256
        //    slots are owned by the hardware.
        mmio_write(self.base, E1000E_RDH, 0);
        let rctl = self.rctl_rx_bits();
        mmio_write(self.base, E1000E_RCTL, rctl);
        let _ = mmio_read(self.base, E1000E_RCTL);
        // Write RDT *after* RCTL_EN so the engine is already running when it
        // sees the doorbell — matches Linux e1000_configure_rx ordering.
        mmio_write(self.base, E1000E_RDT, (NUM_RX - 1) as u32);
        let _ = mmio_read(self.base, E1000E_RDT);

        self.last_hw_rx_packets = mmio_read(self.base, E1000E_GPRC);
        self.kick_rx_writeback();
        self.log_rx_path_regs("RX armed");
    }

    fn maybe_log_rx_diag(&mut self) {
        self.rx_diag_counter = self.rx_diag_counter.wrapping_add(1);
        if self.rx_diag_counter & 0x3F != 0 {
            return;
        }
        let gprc = unsafe { mmio_read(self.base, E1000E_GPRC) };
        if gprc != self.last_hw_rx_packets {

            self.last_hw_rx_packets = gprc;
        }
        let ring = self.rx_ring.as_ptr::<RxDesc>();
        let d0 = unsafe { ring as usize };
        let wb = unsafe { read_volatile((d0 + 8) as *const u32) };
        let rdh = unsafe { mmio_read(self.base, E1000E_RDH) };
        if wb != 0 || rdh != 0 {

        }
    }

    // -----------------------------------------------------------------------
    // Full hardware reset + init
    // -----------------------------------------------------------------------
    unsafe fn reset_and_init(&mut self) -> DeviceResult {
        crate::klog_info!(
            "e1000e: reset_and_init tag={} profile={}\n",
            E1000E_DRIVER_TAG,
            e1000e_profile()
        );
        // Always disable ULP on PCH — conventional mode used to skip this and left RX dead.
        if self.is_pch_lpt_or_later() {
            self.disable_ulp();
        }

        self.read_mac_from_hw();
        let mut mac_found = self.is_valid_mac();

        // PCH I219+: CTRL_RST after UEFI can wedge PCIe (CPU stalls on MMIO).
        let skip_hw_reset = self.is_pch_spt_or_later();

        self.flush_desc_rings();

        if skip_hw_reset {

            mmio_write(self.base, E1000E_WUC, 0);
            mmio_write(self.base, E1000E_WUFC, 0);
            mmio_write(self.base, E1000E_WUS, 0xFFFF_FFFF);
            let ctrl_ext = mmio_read(self.base, E1000E_CTRL_EXT);
            mmio_write(self.base, E1000E_CTRL_EXT, ctrl_ext | (1 << 28));
            // Stop legacy BIOS DMA before reprogramming our descriptor rings.
            self.stop_rx_tx_engines();
            // C8: Skipping PHY_RST as well. Linux only does it if link is down or on errors.
            // Keeping BIOS PHY state often results in a faster and more reliable link-up.
            self.pch_clear_status_phyra_if_set();
        } else {
        let ctrl_ext = mmio_read(self.base, E1000E_CTRL_EXT);
        mmio_write(self.base, E1000E_CTRL_EXT, ctrl_ext | (1 << 28));

        // 3. Issue global reset (RST bit in CTRL).

        let mut ctrl = mmio_read(self.base, E1000E_CTRL);
        mmio_write(self.base, E1000E_CTRL, ctrl | CTRL_GIO_MASTER_DISABLE);
        let mut master_wait = 500; // 500 * 100us = 50ms budget
        while master_wait > 0 {
            if mmio_read(self.base, E1000E_STATUS) & STATUS_GIO_MASTER_ENABLE == 0 {
                break;
            }
            Self::udelay(100); // C1: allow LAPIC timer to advance on bare-metal
            master_wait -= 1;
        }


        ctrl = mmio_read(self.base, E1000E_CTRL);
        mmio_write(self.base, E1000E_CTRL, ctrl | CTRL_RST);

        // Wait for RST self-clear BEFORE touching any other register.
        let mut rst_wait = 1_000; // 1000 * 100us = 100ms budget
        while rst_wait > 0 {
            if mmio_read(self.base, E1000E_CTRL) & CTRL_RST == 0 {
                break;
            }
            Self::udelay(100); // C2: allow LAPIC timer to advance on bare-metal
            rst_wait -= 1;
        }
        // Minimum post-reset silence before any MMIO (datasheet §4.6.3)
        Self::udelay(10_000);

        // Disable Wake-on-LAN now that the reset has completed.
        mmio_write(self.base, E1000E_WUC, 0);
        mmio_write(self.base, E1000E_WUFC, 0);
        mmio_write(self.base, E1000E_WUS, 0xFFFF_FFFF); // W1C: clear any pending WUS bits



        // 3. Poll STATUS until the device is ready.
        // 0xFFFF_FFFF means the PCIe config space is not responding (device
        // absent or bus error). Any other value — including 0 — means the
        // MAC register file is accessible and we can proceed.
        // STATUS_POLL_US = 150ms is the budget for PCH-based NICs (I219).
        let mut ready = false;
        let mut status_poll_tries = (STATUS_POLL_US / 1_000).max(1);
        while status_poll_tries > 0 {
            let s = mmio_read(self.base, E1000E_STATUS);
            if s != 0xFFFF_FFFF {
                ready = true;
                break;
            }
            Self::udelay(1_000);
            status_poll_tries -= 1;
        }
        if !ready {
            warn!("[e1000e] STATUS still 0xFFFFFFFF after {}ms — device not responding", STATUS_POLL_US / 1000);
            return Err(DeviceError::IoError);
        }

        let ctrl_ext = mmio_read(self.base, E1000E_CTRL_EXT);
        mmio_write(self.base, E1000E_CTRL_EXT, ctrl_ext | (1 << 28));
        }

        // 4. Linux Workarounds for I219-V (SPT)
        // NOTE: The is_pch_lpt_or_later() block below (step 6) already applies
        // all necessary FEXTNVM6/FEXTNVM7 workarounds with the correct named
        // constants. The old SPT-only block used raw offsets that mapped to
        // EECD (0x0010) and FEXTNVM4 (0x00E4) — corrupting those registers on
        // real hardware. It has been intentionally removed.

        // 5. Disable interrupts (RST clears IMC, re-enable needed explicitly later)
        mmio_write(self.base, E1000E_IMC, 0xFFFF_FFFF);

        // 5a. Recover the real MAC address FIRST (NVM or HW), THEN write RAL/RAH.
        // Writing RAL/RAH with a still-zero mac[] (from before NVM read) and
        // then overwriting it again later is harmless on QEMU but causes the
        // MAC filter to briefly accept everything on real hardware, which can
        // cause stray frames to fill the RX ring before init finishes.
        if !mac_found {
            // PCH-SPT (I219) and later do NOT use EERD for NVM reads — they use a
            // proprietary flash/firmware mechanism that requires acquiring a firmware
            // semaphore and talking to the CSME. Calling nvm_read_word() on these
            // chips always times out (200 iter × 50µs × 2 attempts = 20ms wasted)
            // and returns 0, which is not the real MAC.
            // For these chips, the BIOS always programs RAL0/RAH0, so the pre-reset
            // read_mac_from_hw() above should already have mac_found = true.
            // We only fall back to EERD-based NVM for discrete silicon (82574L etc.).
            if !self.is_pch_spt_or_later() {
                self.read_mac_from_nvm();
                mac_found = self.is_valid_mac();
            } else {
                // For I219 and later: re-read RAL0/RAH0 post-reset.
                // The reset may have reloaded the NVM shadow registers from flash.
                self.read_mac_from_hw();
                mac_found = self.is_valid_mac();
            }
        }
        if !mac_found {
            self.read_mac_from_hw();
            mac_found = self.is_valid_mac();
        }
        if !mac_found {
            self.mac = [0x00, 0x0E, 0x10, 0x00, 0x0E, 0x00];
            warn!("[e1000e] using fallback MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                self.mac[0], self.mac[1], self.mac[2], self.mac[3], self.mac[4], self.mac[5]);
        }

        // 5b. Write the resolved MAC into RAL0/RAH0 with AV bit.
        let mac_low = u32::from_le_bytes([self.mac[0], self.mac[1], self.mac[2], self.mac[3]]);
        let mac_high = u32::from_le_bytes([self.mac[4], self.mac[5], 0, 0]);
        mmio_write(self.base, E1000E_RAL0, mac_low);
        mmio_write(self.base, E1000E_RAH0, mac_high | 0x80000000); // AV bit
        // Clear all other receive address slots.
        // Each slot is 8 bytes = 2 u32 dwords: RAL[i] @ RAL0+i*2, RAH[i] @ RAL0+i*2+1.
        // C5: Using RAH0+i*2 was incorrect — RAH0 = RAL0+1, so RAH0+i*2 != RAL0+i*2+1
        // for i>0. The correct stride keeps RAL and RAH within the same 8-byte slot.
        for i in 1usize..16 {
            mmio_write(self.base, E1000E_RAL0 + i * 2,     0); // RAL[i]
            mmio_write(self.base, E1000E_RAL0 + i * 2 + 1, 0); // RAH[i] = RAL[i]+1
        }

        // 6. Basic MAC configuration
        let ctrl = mmio_read(self.base, E1000E_CTRL);
        mmio_write(
            self.base,
            E1000E_CTRL,
            (ctrl | CTRL_SLU | CTRL_ASDE | CTRL_FD) & !(CTRL_TFCE | CTRL_RFCE | CTRL_VME | CTRL_GIO_MASTER_DISABLE),
        );

        let mut ctrl_ext = mmio_read(self.base, E1000E_CTRL_EXT);
        ctrl_ext |= 1 << 22; // PBA_CLR
        ctrl_ext |= 1 << 31; // PBA_SUPPORT (I219)
        ctrl_ext |= 1 << 28; // INT_TIMER_CLR
        if self.is_pch_lpt_or_later() {
            // Linux sets PHYPDEN for D3 low-power; on several I219 systems that
            // keeps STATUS.LU cleared after driver init without a full MAC reset.
            ctrl_ext &= !CTRL_EXT_PHYPDEN;
        }
        ctrl_ext |= CTRL_EXT_RO_DIS;
        ctrl_ext &= !CTRL_EXT_DPG_EN;
        mmio_write(self.base, E1000E_CTRL_EXT, ctrl_ext);

        if self.is_pch_lpt_or_later() {
            // PBA: 26K RX, 18K TX (PCH default)
            mmio_write(self.base, E1000E_PBA, 0x0012001A);
        } else {
            mmio_write(self.base, E1000E_PBA, 0x00100030);
        }

        // PCH workarounds required on real I219 even in conventional profile (Linux ich8lan).
        if self.is_pch_lpt_or_later() {
            self.pch_apply_silicon_workarounds();
        }

        if !E1000E_CONVENTIONAL && self.is_pch_lpt_or_later() {
            mmio_write(self.base, E1000E_CRC_OFFSET, 0x65656565);
            let kabgtxd = mmio_read(self.base, E1000E_KABGTXD);
            mmio_write(self.base, E1000E_KABGTXD, kabgtxd | KABGTXD_BGSQLBIAS);

            let mut fextnvm6 = mmio_read(self.base, E1000E_FEXTNVM6);
            fextnvm6 |= FEXTNVM6_K1_OFF_EN | FEXTNVM6_DIS_ELDW;
            mmio_write(self.base, E1000E_FEXTNVM6, fextnvm6);

            let mut kmrn = self.kmrn_read(KMRNCTRLSTA_K1_CONFIG);
            kmrn &= !KMRNCTRLSTA_K1_ENABLE;
            self.kmrn_write(KMRNCTRLSTA_K1_CONFIG, kmrn);

            let mut fextnvm11 = mmio_read(self.base, E1000E_FEXTNVM11);
            fextnvm11 |= FEXTNVM11_DISABLE_L1_2;
            mmio_write(self.base, E1000E_FEXTNVM11, fextnvm11);

            let mut fextnvm4 = mmio_read(self.base, E1000E_FEXTNVM4);
            fextnvm4 &= !FEXTNVM4_BEACON_DURATION_MASK;
            fextnvm4 |= FEXTNVM4_BEACON_DURATION_8USEC;
            mmio_write(self.base, E1000E_FEXTNVM4, fextnvm4);

            let mut fextnvm7 = mmio_read(self.base, E1000E_FEXTNVM7);
            fextnvm7 |= FEXTNVM7_SIDE_CLK_UNGATE
                | FEXTNVM7_DISABLE_SMB_PERST
                | FEXTNVM7_NEED_DESCR_RING_FLUSH;
            mmio_write(self.base, E1000E_FEXTNVM7, fextnvm7);

            let mut fextnvm9 = mmio_read(self.base, E1000E_FEXTNVM9);
            fextnvm9 |= FEXTNVM9_IOSFSB_CLKGATE_DIS | FEXTNVM9_IOSFSB_CLKREQ_DIS;
            mmio_write(self.base, E1000E_FEXTNVM9, fextnvm9);

            if matches!(self.device_id, 0x156f..=0x1570 | 0x15b7..=0x15be) {
                let iosfpc = mmio_read(self.base, E1000E_IOSFPC);
                mmio_write(self.base, E1000E_IOSFPC, iosfpc | 0x00010000);
            }
        }

        if !E1000E_CONVENTIONAL {
            let mut tarc0 = mmio_read(self.base, E1000E_TARC0);
            tarc0 |= (1 << 23) | (1 << 24) | (1 << 26) | (1 << 27);
            mmio_write(self.base, E1000E_TARC0, tarc0);

            let mut tarc1 = mmio_read(self.base, E1000E_TARC1);
            tarc1 |= (1 << 24) | (1 << 26) | (1 << 30) | (1 << 28);
            mmio_write(self.base, E1000E_TARC1, tarc1);
        }

        // 7. RAL0/RAH0 already written above (step 5b) with the correct MAC.
        // No second write needed; keeping the block for reference only.
        let _ = mac_found; // suppress unused-variable warning

        // 8. Clear MTA
        for i in 0..E1000E_MTA_LEN {
            mmio_write(self.base, E1000E_MTA_BASE + i, 0);
        }

        // 9. Initialize Rings
        let rx_ring = self.rx_ring.as_ptr::<RxDesc>();
        let tx_ring = self.tx_ring.as_ptr::<TxDesc>();
        core::ptr::write_bytes(rx_ring, 0, NUM_RX);
        core::ptr::write_bytes(tx_ring, 0, NUM_TX);
        for i in 0..NUM_RX {
            let desc = &mut *rx_ring.add(i);
            desc.addr = self.rx_bufs[i].paddr() as u64;
            core::arch::x86_64::_mm_clflush(desc as *const RxDesc as *const u8);
        }
        for i in 0..NUM_TX {
            let desc = &mut *tx_ring.add(i);
            desc.status = 0x01; // DD=1: descriptor initially available
            core::arch::x86_64::_mm_clflush(desc as *const TxDesc as *const u8);
        }
        fence(Ordering::SeqCst);

        // 10. Configure TX
        let tx_ring_pa = self.tx_ring.paddr();
        mmio_write(self.base, E1000E_TDBAL, tx_ring_pa as u32);
        mmio_write(self.base, E1000E_TDBAH, (tx_ring_pa >> 32) as u32);
        mmio_write(self.base, E1000E_TDLEN, (NUM_TX * size_of::<TxDesc>()) as u32);
        mmio_write(self.base, E1000E_TDH, 0);
        mmio_write(self.base, E1000E_TDT, 0);
        mmio_write(self.base, E1000E_TIPG, 8 | (8 << 10) | (12 << 20));
        mmio_write(self.base, E1000E_TIDV, 0);
        mmio_write(self.base, E1000E_TADV, 0);

        // TXDCTL and Queue Enable
        mmio_write(self.base, E1000E_TXDCTL, TXDCTL_GRAN | TXDCTL_FULL_TX_DESC_WB | TXDCTL_COUNT_DESC | 31);
        if self.is_pch_spt_or_later() {
            // PCH-SPT (I219+) requires explicit QUEUE_ENABLE (bit 25) to start TX DMA.
            let txdctl = mmio_read(self.base, E1000E_TXDCTL);
            mmio_write(self.base, E1000E_TXDCTL, txdctl | TXDCTL_QUEUE_ENABLE);
            let mut txq_wait = 100; // 100 * 100us = 10ms
            while txq_wait > 0 && mmio_read(self.base, E1000E_TXDCTL) & TXDCTL_QUEUE_ENABLE == 0 {
                Self::udelay(100); // C3: allow timer to tick on bare-metal
                txq_wait -= 1;
            }
        }
        if !E1000E_CONVENTIONAL {
            mmio_write(
                self.base,
                E1000E_TXDCTL1,
                mmio_read(self.base, E1000E_TXDCTL),
            );
        }
        {
            let mut tctl = mmio_read(self.base, E1000E_TCTL);
            if E1000E_CONVENTIONAL {
                tctl |= TCTL_EN | TCTL_PSP;
            } else {
                tctl &= !(0xFF0u32 | 0x003FF000u32);
                tctl |= TCTL_EN | TCTL_PSP | TCTL_RTLC | TCTL_CT_LINUX | TCTL_COLD_LINUX;
            }
            mmio_write(self.base, E1000E_TCTL, tctl);
            let _ = mmio_read(self.base, E1000E_TCTL);
        }

        // M5: MTA was already cleared above (step 8). Remove duplicate.
        
        // Signal driver loaded
        let ctrl_ext = mmio_read(self.base, E1000E_CTRL_EXT);
        mmio_write(self.base, E1000E_CTRL_EXT, ctrl_ext | (1 << 28));

        // 11. Configure RX — register order aligned with Linux e1000_configure_rx:
        // RDTR/RADV/ITR → IAME/IAM → RDBAL/RDBAH/RDLEN/RDH/RDT → RXCSUM/RFCTL/…
        mmio_write(self.base, E1000E_RDTR, 0);
        mmio_write(self.base, E1000E_RADV, 0);
        mmio_write(self.base, E1000E_ITR, 0);
        // Linux e1000_configure_rx: IAME + IAM mask all sources.
        {
            let mut ce = mmio_read(self.base, E1000E_CTRL_EXT);
            ce |= CTRL_EXT_IAME;
            mmio_write(self.base, E1000E_IAM, 0xFFFF_FFFF);
            mmio_write(self.base, E1000E_CTRL_EXT, ce);
            let _ = mmio_read(self.base, E1000E_CTRL_EXT);
        }

        let rx_ring_pa = self.rx_ring.paddr();
        mmio_write(self.base, E1000E_RDBAL, rx_ring_pa as u32);
        mmio_write(self.base, E1000E_RDBAH, (rx_ring_pa >> 32) as u32);
        mmio_write(self.base, E1000E_RDLEN, (NUM_RX * size_of::<RxDesc>()) as u32);
        mmio_write(self.base, E1000E_RDH, 0);
        mmio_write(self.base, E1000E_RDT, (NUM_RX - 1) as u32);
        self.rx_tail = 0;



        mmio_write(self.base, E1000E_RXCSUM, 0);
        // Linux e1000_setup_rctl: EXTEN on all e1000e (required on I219 real HW).
        {
            let mut rfctl = mmio_read(self.base, E1000E_RFCTL);
            rfctl |= RFCTL_EXTEN | RFCTL_NFSW_DIS | RFCTL_NFSR_DIS;
            mmio_write(self.base, E1000E_RFCTL, rfctl);
            let rfctl_rd = mmio_read(self.base, E1000E_RFCTL);
            if rfctl_rd & RFCTL_EXTEN == 0 {
                crate::klog_warn!("[e1000e] RFCTL EXTEN missing after write! ({:#x})\n", rfctl_rd);
            }
        }
        mmio_write(self.base, E1000E_MRQC, 0);
        mmio_write(self.base, E1000E_VET, 0);
        
        // SRRCTL: buffer size 2 KB + Drop Enable (bit 31).
        // Bits [3:0] = buffer size in 1 KB units → 2 = 2 KB.
        // Bit 31 (Drop_En) tells hardware to silently drop frames when the
        // ring is full instead of generating a PCIe error / hanging.
        // Without Drop_En the I219 can stall the TX path when RX overflows.
        mmio_write(self.base, E1000E_SRRCTL, 2 | (1 << 31));

        if self.is_pch_lpt_or_later() {
            mmio_write(self.base, E1000E_FCTTV, 0xFFFF);
            mmio_write(self.base, E1000E_FCRTV, 0xFFFF);
            mmio_write(self.base, E1000E_FCRTL, 0x05048);
            mmio_write(self.base, E1000E_FCRTH, 0x05C20);
        }

        if self.is_pch_lpt_or_later() {
            self.pch_setup_kmrn_copper_link();
        }

        self.program_rxdctl();

        // Keep receiver disabled until link is up (I219 RX engine breaks if enabled too early).
        mmio_write(self.base, E1000E_RCTL, mmio_read(self.base, E1000E_RCTL) & !RCTL_EN);


        // Disable VLAN filtering
        mmio_write(self.base, E1000E_VET, 0);
        for i in 0..128 { mmio_write(self.base, E1000E_VFTA_BASE + i, 0); } // Clear VFTA table
        let rctl_v = mmio_read(self.base, E1000E_RCTL);
        mmio_write(self.base, E1000E_RCTL, rctl_v & !RCTL_VFE);

        self.mac_setup_copper_link_linux();

        // Disable EEE
        mmio_write(self.base, 0x0E30 / 4, 0);

        let _ = mmio_read(self.base, E1000E_ICR);
        mmio_write(self.base, E1000E_IMS, IMS_REARM_LINUX);

        // 13. Link status. Conventional: short PHY kick only; extended: full settle.
        let mut status = mmio_read(self.base, E1000E_STATUS);
        if E1000E_CONVENTIONAL && status & STATUS_LU == 0 && self.is_pch_spt_or_later() {
            self.pch_issue_phy_reset();
            self.pch_kick_autoneg_mdio();
            let _ = self.pch_sync_mac_from_phy();
            for _ in 0..40 {
                Self::udelay(50_000);
                status = mmio_read(self.base, E1000E_STATUS);
                if status & STATUS_LU != 0 {
                    break;
                }
            }
        } else if status & STATUS_LU == 0 && self.is_pch_spt_or_later() {
            // Linux always PHY-resets during MAC reset; we skip CTRL_RST on I219+ to
            // avoid PCIe hangs, so kick the PHY once before the long settle loop.
            crate::klog_warn!("[e1000e] link down, issuing PCH PHY_RST before settle\n");
            self.pch_issue_phy_reset();
            for _ in 0..40 {
                Self::udelay(50_000);
                status = mmio_read(self.base, E1000E_STATUS);
                if status & STATUS_LU != 0 {
                    crate::klog_info!(
                        "[e1000e] link up after PHY_RST ({:#x})\n",
                        status
                    );
                    break;
                }
            }
        }
        if status & STATUS_LU == 0 && self.is_pch_spt_or_later() {
            crate::klog_warn!("[e1000e] link down, waiting for settlement...\n");
            const PCH_LINK_SETTLE_TOTAL_MS: u32 = 3000;
            const STEP_US: u64 = 50_000;
            let steps = (PCH_LINK_SETTLE_TOTAL_MS as u64 * 1000 / STEP_US).max(1);
            for i in 0..steps {
                Self::udelay(STEP_US);
                status = mmio_read(self.base, E1000E_STATUS);
                if status & STATUS_LU != 0 {
                    crate::klog_info!("[e1000e] link came up after {}ms\n", i * 50);
                    break;
                }
                if i % 10 == 0 {
                    for phy_addr in [1u8, 2u8] {
                        if let Some(bmsr) = self.mdic_read(phy_addr, MII_BMSR) {
                            if bmsr == 0 || bmsr == 0xFFFF {
                                continue;
                            }
                            let pss = self.mdic_read(phy_addr, 17).unwrap_or(0);
                            let st2 = self.mdic_read(phy_addr, MII_PHY_STATUS_2).unwrap_or(0);

                            if bmsr & 0x0004 != 0 && self.pch_sync_mac_from_phy() {
                                status = mmio_read(self.base, E1000E_STATUS);
                                break;
                            }
                        }
                    }
                    if status & STATUS_LU != 0 {
                        break;
                    }
                }
            }
            if status & STATUS_LU == 0 {
                crate::klog_warn!("[e1000e] STATUS.LU still 0 after settle — trying autoneg restart\n");
                self.pch_kick_autoneg_mdio();
                let _ = self.pch_sync_mac_from_phy();
                // Wait up to 6s post-MDIO restart; I219-V cold autoneg can take 4-5s
                const AFTER_MDIO_MS: u32 = 6000;
                let steps2 = (AFTER_MDIO_MS as u64 * 1000 / STEP_US).max(1);
                for i in 0..steps2 {
                    Self::udelay(STEP_US);
                    status = mmio_read(self.base, E1000E_STATUS);
                    if status & STATUS_LU != 0 {
                        crate::klog_info!("[e1000e] link up after MDIO restart ({}ms)\n", i * 50);
                        break;
                    }
                    // Every 1s log current status so we can see progress

                }
            }
            if status & STATUS_LU == 0 {
                crate::klog_warn!(
                    "[e1000e] link still down after MDIO restart — toggling LANPHYPC recovery path\n"
                );
                self.toggle_lanphypc();
                self.pch_kick_autoneg_mdio();
                const AFTER_LANPHYPC_MS: u32 = 3000;
                let steps3 = (AFTER_LANPHYPC_MS as u64 * 1000 / STEP_US).max(1);
                for i in 0..steps3 {
                    Self::udelay(STEP_US);
                    status = mmio_read(self.base, E1000E_STATUS);
                    if status & STATUS_LU != 0 {
                        crate::klog_info!("[e1000e] link up after LANPHYPC recovery ({}ms)\n", i * 50);
                        break;
                    }

                }
            }
        }
        if status & STATUS_LU == 0 {
            crate::klog_warn!("e1000e: NIC Link is Down (Final STATUS={:#x})\n", status);
            if self.is_pch_spt_or_later() {
                crate::klog_warn!(
                    "[e1000e] forcing RX ring re-arm despite LU=0 (real HW fallback)\n"
                );
                self.mac_allow_autoneg();
                self.enable_rx_after_link();
            }
        } else {
            crate::klog_info!("e1000e: NIC Link is Up\n");
            self.mac_allow_autoneg();
            self.enable_rx_after_link();
        }

        crate::klog_info!(
            "e1000e: init complete tag={} profile={} STATUS={:#010x} link={}\n",
            E1000E_DRIVER_TAG,
            e1000e_profile(),
            status,
            if status & STATUS_LU != 0 { "up" } else { "down" }
        );
        Ok(())
    }

    unsafe fn restore_ctrl_autoneg_after_link(&self) {
        self.mac_setup_copper_link_linux();
    }

    /// Re-post RX descriptors (addr valid, write-back region cleared).
    unsafe fn reinit_rx_ring(&mut self) {
        let ring = self.rx_ring.as_ptr::<RxDesc>();
        for i in 0..NUM_RX {
            let desc = &mut *ring.add(i);
            desc.addr = self.rx_bufs[i].paddr() as u64;
            write_volatile((desc as *mut RxDesc as usize + 8) as *mut u64, 0);
            core::arch::x86_64::_mm_clflush(desc as *const RxDesc as *const u8);
        }
        fence(Ordering::SeqCst);
        self.rx_tail = 0;
    }

    /// Re-arm RX/TX once link is up (after LANPHYPC / late LU / LSC).
    unsafe fn refresh_datapath_after_link(&mut self) {
        mmio_write(self.base, E1000E_TDH, 0);
        mmio_write(self.base, E1000E_TDT, 0);
        self.tx_tail = 0;
        self.mac_allow_autoneg();
        self.enable_rx_after_link();
        let _ = mmio_read(self.base, E1000E_ICR);
    }

    /// Hardware MIB counters (Linux `e1000e_update_stats`). Clear-on-read.
    unsafe fn read_hw_stats(&self) -> NetStats {
        let rx_packets = mmio_read(self.base, E1000E_GPRC) as u64;
        let tx_packets = mmio_read(self.base, E1000E_GPTC) as u64;
        let rx_bytes =
            (mmio_read(self.base, E1000E_GORCL) as u64) | ((mmio_read(self.base, E1000E_GORCH) as u64) << 32);
        let tx_bytes =
            (mmio_read(self.base, E1000E_GOTCL) as u64) | ((mmio_read(self.base, E1000E_GOTCH) as u64) << 32);
        let mpc = mmio_read(self.base, E1000E_MPC) as u64;
        NetStats {
            rx_bytes,
            rx_packets,
            tx_bytes,
            tx_packets,
            rx_errors: 0,
            rx_dropped: mpc,
            tx_errors: 0,
            tx_dropped: 0,
        }
    }

    fn merged_stats(&self) -> NetStats {
        self.stats.clone()
    }

    /// Returns (staterr, len) if an extended write-back descriptor is done.
    /// We always use RFCTL_EXTEN on I219, so only check the extended layout:
    ///   +8  u32 staterr  (DD=bit0, EOP=bit1)
    ///   +12 u16 length
    unsafe fn desc_done(desc_addr: usize) -> Option<(u32, usize)> {
        Self::dma_inv_desc(desc_addr);
        let staterr = read_volatile((desc_addr + 8) as *const u32);
        if staterr & RXD_EXT_DD != 0 {
            let len = read_volatile((desc_addr + 12) as *const u16) as usize;
            return Some((staterr, len));
        }
        None
    }

    /// Nudge the MAC to write back completed RX descriptors (Linux RDTR_FPD path).
    unsafe fn kick_rx_writeback(&self) {
        mmio_write(self.base, E1000E_RDTR, RDTR_FPD);
        let _ = mmio_read(self.base, E1000E_RDTR);
        mmio_write(self.base, E1000E_RDTR, 0);
        let _ = mmio_read(self.base, E1000E_RDTR);
    }

    fn receive_at(&mut self, idx: usize) -> Option<Vec<u8>> {
        let ring = self.rx_ring.as_ptr::<RxDesc>();
        let desc_addr = unsafe { ring.add(idx) as usize };
        let (staterr, len) = unsafe { Self::desc_done(desc_addr)? };
        fence(Ordering::Acquire);

        if staterr & RXD_EXT_EOP == 0 {
            // Multi-fragment frame — not supported in this driver, drop and recycle.
            warn!("[e1000e] RX: DD without EOP at slot {} staterr={:#x} — dropped", idx, staterr);
            // Recycle the descriptor so hardware can reuse it.
            unsafe {
                write_volatile((desc_addr + 8) as *mut u64, 0);
                Self::dma_wbinv_range(desc_addr, core::mem::size_of::<RxDesc>());
                // Give this slot back to the hardware by writing its index to RDT.
                mmio_write(self.base, E1000E_RDT, idx as u32);
                let _ = mmio_read(self.base, E1000E_RDT);
            }
            self.rx_tail = (idx + 1) % NUM_RX;
            return None;
        }

        if len == 0 || len > BUF_SIZE {
            // Recycle bad descriptor.
            unsafe {
                write_volatile((desc_addr + 8) as *mut u64, 0);
                Self::dma_wbinv_range(desc_addr, core::mem::size_of::<RxDesc>());
                mmio_write(self.base, E1000E_RDT, idx as u32);
                let _ = mmio_read(self.base, E1000E_RDT);
            }
            self.rx_tail = (idx + 1) % NUM_RX;
            return None;
        }

        // Copy payload BEFORE clearing the descriptor so the hardware does not
        // overwrite the buffer while we are still reading it.
        let buf_vaddr = self.rx_bufs[idx].vaddr();
        let mut data = Vec::new();
        unsafe { Self::dma_copy_in(&mut data, buf_vaddr, len) };

        // Clear the write-back region so desc_done() does not see stale DD on
        // the next pass through this slot, then flush to RAM so the HW sees it.
        unsafe {
            write_volatile((desc_addr + 8) as *mut u64, 0);
            Self::dma_wbinv_range(desc_addr, core::mem::size_of::<RxDesc>());
            // Advance RDT to 'idx': we are giving slot 'idx' back to hardware.
            // The hardware owns all slots from RDH up to (but not including) RDT+1;
            // writing idx means "slot idx is now free for the hardware".
            mmio_write(self.base, E1000E_RDT, idx as u32);
            let _ = mmio_read(self.base, E1000E_RDT);
        }

        self.rx_tail = (idx + 1) % NUM_RX;



        self.stats.rx_packets += 1;
        self.stats.rx_bytes += len as u64;
        Some(data)
    }

    fn receive(&mut self) -> Option<Vec<u8>> {
        let rdh = unsafe { mmio_read(self.base, E1000E_RDH) as usize };
        if rdh != self.rx_tail {
            unsafe { self.kick_rx_writeback() };
        }

        if let Some(pkt) = self.receive_at(self.rx_tail) {
            return Some(pkt);
        }

        for off in 1..NUM_RX {
            let i = (self.rx_tail + off) % NUM_RX;
            let ring = self.rx_ring.as_ptr::<RxDesc>();
            let desc_addr = unsafe { ring.add(i) as usize };
            if unsafe { Self::desc_done(desc_addr) }.is_some() {
                crate::klog_warn!(
                    "e1000e: RX DD at slot {} (tail={} RDH={}) — tail desync, resyncing\n",
                    i,
                    self.rx_tail,
                    rdh
                );
                // Skip over any slots between rx_tail and i by recycling them.
                while self.rx_tail != i {
                    let skip = self.rx_tail;
                    let skip_addr = unsafe { ring.add(skip) as usize };
                    unsafe {
                        write_volatile((skip_addr + 8) as *mut u64, 0);
                        Self::dma_wbinv_range(skip_addr, core::mem::size_of::<RxDesc>());
                        mmio_write(self.base, E1000E_RDT, skip as u32);
                        let _ = mmio_read(self.base, E1000E_RDT);
                    }
                    self.rx_tail = (skip + 1) % NUM_RX;
                }
                return self.receive_at(i);
            }
        }
        None
    }

    // -----------------------------------------------------------------------
    // Check if a TX slot is available
    // -----------------------------------------------------------------------
    fn can_send(&self) -> bool {
        let ring = self.tx_ring.as_ptr::<TxDesc>();
        let idx = self.tx_tail;
        let desc = unsafe { &*ring.add(idx) };
        let status = unsafe { read_volatile(&desc.status) };
        fence(Ordering::Acquire);
        status & 0x01 != 0 // DD bit
    }

    // -----------------------------------------------------------------------
    // Send one frame
    // -----------------------------------------------------------------------
    pub fn send(&mut self, data: &[u8]) -> DeviceResult {
        if data.len() < 14 {
            return Err(DeviceError::InvalidParam);
        }
        let eth_type = u16::from_be_bytes([data[12], data[13]]);
        let info = match eth_type {
            0x0806 => "ARP",
            0x0800 => {
                let proto = if data.len() >= 24 { data[23] } else { 0 };
                match proto {
                    1 => "IPv4-ICMP",
                    6 => "IPv4-TCP",
                    17 => "IPv4-UDP",
                    _ => "IPv4-Other",
                }
            }
            0x86dd => "IPv6",
            _ => "Other",
        };

        // warn!("[e1000e] TX: {} ({} bytes)", info, data.len());

        if !self.can_send() {
            return Err(DeviceError::NotReady);
        }
        if data.is_empty() || data.len() > BUF_SIZE {
            return Err(DeviceError::InvalidParam);
        }

        let ring = self.tx_ring.as_ptr::<TxDesc>();
        let idx = self.tx_tail;
        let desc = unsafe { &mut *ring.add(idx) };

        let buf =
            unsafe { core::slice::from_raw_parts_mut(self.tx_bufs[idx].vaddr() as *mut u8, data.len()) };
        buf.copy_from_slice(data);


        // Track stats
        self.stats.tx_packets += 1;
        self.stats.tx_bytes += data.len() as u64;

        unsafe {
            write_volatile(&mut desc.addr, self.tx_bufs[idx].paddr() as u64);
            write_volatile(&mut desc.len, data.len() as u16);
            // Linux e1000_tx_desc: zero cso/css/special unless offload is used.
            write_volatile(&mut desc.cso, 0);
            write_volatile(&mut desc.cmd, TX_CMD_EOP | TX_CMD_IFCS | TX_CMD_RS);
            write_volatile(&mut desc.status, 0);
            write_volatile(&mut desc.css, 0);
            write_volatile(&mut desc.special, 0);
        }
        fence(Ordering::SeqCst);

        // CPU → device: push data and descriptor to physical RAM before ringing TDT.
        // _mm_clflush writes dirty WB cache lines back and invalidates them.
        // _mm_sfence is required on top of clflush to drain write-combining (WC)
        // buffers — on real hardware DMA memory may be mapped WC, in which case
        // clflush alone does NOT flush WC stores. QEMU doesn't simulate WC so this
        // difference explains why TX works in QEMU but silently fails on I219-V.
        unsafe {
            Self::dma_wbinv_range(self.tx_bufs[idx].vaddr(), data.len());
            Self::dma_wbinv_range(desc as *const TxDesc as usize, core::mem::size_of::<TxDesc>());
            // Store fence: all stores (including WC) visible before TDT doorbell.
            core::arch::x86_64::_mm_sfence();
        }

        self.tx_tail = (idx + 1) % NUM_TX;
        unsafe { 
            mmio_write(self.base, E1000E_TDT, self.tx_tail as u32);
            let _ = mmio_read(self.base, E1000E_TDT); // serialise MMIO write
        }

        // Wait for RS write-back (DD) so the next frame does not stomp an in-flight TX.
        for _ in 0..200 {
            unsafe {
                let st = read_volatile(&(*ring.add(idx)).status);
                if st & 0x01 != 0 {
                    break;
                }
            }
            Self::udelay(50);
        }



        Ok(())
    }

}

impl Drop for E1000eHw {
    fn drop(&mut self) {
        // DmaRegion handles its own deallocation
    }
}

// ---------------------------------------------------------------------------
// Public driver wrapper
// ---------------------------------------------------------------------------
#[derive(Clone)]
pub struct E1000eDriver {
    pub hw: Arc<Mutex<E1000eHw>>,
}

#[derive(Clone)]
pub struct E1000eInterface {
    pub iface: Arc<Mutex<Interface<'static, E1000eDriver>>>,
    pub driver: E1000eDriver,
    pub name: String,
    pub irq: usize,
    pub base: usize,
    pub poll_pending: Arc<core::sync::atomic::AtomicBool>,
    pub link_up_seen: Arc<core::sync::atomic::AtomicBool>,
    pub routes: Arc<Mutex<Vec<RouteInfo>>>,
}

impl E1000eInterface {
    fn ims_rearm(&self) {
        unsafe {
            mmio_write(self.base, E1000E_IMS, IMS_REARM_LINUX);
            let _ = mmio_read(self.base, E1000E_IMS);
        }
    }
}

impl Scheme for E1000eInterface {
    fn name(&self) -> &str {
        "e1000e"
    }

    fn handle_irq(&self, irq: usize) {
        if irq != self.irq {
            return;
        }

        // ICR is Read-to-Clear: reading it both acknowledges the interrupt at
        // the hardware level and tells us what triggered it. We must do this
        // exactly ONCE per IRQ entry. A second read would always return 0
        // because the first read already cleared all bits — causing us to
        // miss the RX event and never wake the polling loop.
        let icr = unsafe { mmio_read(self.base, E1000E_ICR) };
        if icr == 0 {
            self.ims_rearm();
            return;
        }

        if icr & (1 << 2) != 0 {
            let status = unsafe { mmio_read(self.base, E1000E_STATUS) };
            if status & STATUS_LU != 0 {
                let transitioned_up = !self
                    .link_up_seen
                    .swap(true, core::sync::atomic::Ordering::SeqCst);
                crate::klog_info!(
                    "{}: NIC Link is Up{}\n",
                    self.name,
                    if transitioned_up { "" } else { " (stable)" }
                );
                let mut hw = self.driver.hw.lock();
                unsafe {
                    hw.apply_link_adjustments_linux();
                    if transitioned_up {
                        hw.refresh_datapath_after_link();
                    }
                }
            } else {
                self.link_up_seen
                    .store(false, core::sync::atomic::Ordering::SeqCst);
                crate::klog_warn!("{}: NIC Link is Down\n", self.name);
            }
        }

        if !self.poll_pending.load(core::sync::atomic::Ordering::SeqCst) {
            self.poll_pending.store(true, core::sync::atomic::Ordering::SeqCst);
            let poll_pending = self.poll_pending.clone();
            let self_clone = self.clone();
            crate::utils::deferred_job::push_deferred_job(move || {
                let _ = self_clone.poll();
                poll_pending.store(false, core::sync::atomic::Ordering::SeqCst);
            });
        } else {
            self.ims_rearm();
        }
    }
}

impl NetScheme for E1000eInterface {
    fn get_mac(&self) -> EthernetAddress {
        self.iface.lock().ethernet_addr()
    }
    fn get_ifname(&self) -> String {
        self.name.clone()
    }
    fn get_ip_address(&self) -> Vec<IpCidr> {
        Vec::from(self.iface.lock().ip_addrs())
    }
    fn set_ipv4_address(&self, cidr: Ipv4Cidr) -> DeviceResult {
        crate::klog_info!("{}: IPv4 address set to {}", self.name, cidr);
        self.iface.lock().update_ip_addrs(|addrs| {
            if let Some(addr) = addrs
                .iter_mut()
                .find(|addr| matches!(addr, IpCidr::Ipv4(_)))
            {
                *addr = IpCidr::Ipv4(cidr);
            } else if let Some(addr) = addrs.iter_mut().next() {
                *addr = IpCidr::Ipv4(cidr);
            }
        });
        Ok(())
    }
    
    fn poll(&self) -> DeviceResult {
        let ts = Instant::from_micros(timer_now_as_micros() as i64);
        let sockets = get_sockets();

        crate::utils::deferred_job::drain_deferred_jobs();

        let flag = intr_get();
        if flag {
            intr_off();
        }

        // Drain the hardware RX ring into AF_PACKET queues (edhcpc) before smoltcp.
        // One smoltcp poll only pulls a single frame via Device::receive.
        {
            let mut drained = 0usize;
            loop {
                let pkt = self.driver.hw.lock().receive();
                if let Some(data) = pkt {
                    super::net_dispatch_packet(&data);
                    drained += 1;
                } else {
                    break;
                }
            }
            if drained == 0 {
                self.driver.hw.lock().maybe_log_rx_diag();
            }
        }

        {
            let mut sockets = sockets.lock();
            let _ = self.iface.lock().poll(&mut sockets, ts);
        }
        self.ims_rearm();

        if flag {
            intr_on();
        }
        Ok(())
    }
    fn recv(&self, buf: &mut [u8]) -> DeviceResult<usize> {
        let pkt = self.driver.hw.lock().receive();
        if let Some(pkt) = pkt {

            let n = pkt.len().min(buf.len());
            buf[..n].copy_from_slice(&pkt[..n]);
            Ok(n)
        } else {
            Err(DeviceError::NotReady)
        }
    }
    fn send(&self, data: &[u8]) -> DeviceResult<usize> {

        let mut hw = self.driver.hw.lock();
        if hw.can_send() {
            hw.send(data)?;
            Ok(data.len())
        } else {
            warn!("[e1000e] send: hardware not ready");
            Err(DeviceError::NotReady)
        }
    }

    fn can_recv(&self) -> bool {
        // Return true so callers always attempt recv(); actual receive will return NotReady if nothing.
        true
    }

    fn can_send(&self) -> bool {
        self.driver.hw.lock().can_send()
    }

    fn add_route(&self, cidr: IpCidr, gateway: Option<smoltcp::wire::IpAddress>) -> DeviceResult {

        let mut iface = self.iface.lock();
        match (cidr, gateway) {
            (IpCidr::Ipv4(c), Some(IpAddress::Ipv4(gw))) if c.prefix_len() == 0 => {
                iface
                    .routes_mut()
                    .add_default_ipv4_route(gw)
                    .map_err(|_| DeviceError::IoError)?;
                
                let mut routes = self.routes.lock();
                routes.retain(|r| r.dst.prefix_len() != 0);
                routes.push(RouteInfo {
                    dst: cidr,
                    gateway: Some(IpAddress::Ipv4(gw)),
                });
            }
            _ => {
                warn!("[e1000e] non-default routes are not yet fully supported by this smoltcp version; tracking in driver only");
                self.routes.lock().push(RouteInfo { dst: cidr, gateway });
            }
        }

        Ok(())
    }

    fn del_route(&self, cidr: IpCidr, _gateway: Option<smoltcp::wire::IpAddress>) -> DeviceResult {

        let mut iface = self.iface.lock();
        if let IpCidr::Ipv4(c) = cidr {
            if c.prefix_len() == 0 {
                // iface.routes_mut().remove_default_ipv4_route(); // Might not exist
                // Set to unspecified if needed, or just let it be if we can't remove.
            }
        }
        self.routes.lock().retain(|r| r.dst != cidr);
        Ok(())
    }

    fn get_routes(&self) -> Vec<RouteInfo> {
        let iface = self.iface.lock();
        let mut res = Vec::new();
        
        // 1. Add tracked routes (including default gateway)
        res.extend(self.routes.lock().clone());
        
        // 2. Add direct routes for each assigned IP address
        for cidr in iface.ip_addrs() {
            if let IpCidr::Ipv4(v4) = cidr {
                if v4.prefix_len() > 0 {
                    // Use v4.network() directly if it returns IpCidr
                    res.push(RouteInfo {
                        dst: IpCidr::Ipv4(v4.network()),
                        gateway: None,
                    });
                }
            }
        }
        res
    }

    fn get_stats(&self) -> NetStats {
        self.driver.hw.lock().merged_stats()
    }
    fn get_arp_content(&self) -> String {
        use alloc::fmt::Write;
        let mut s = String::new();
        // Do not call get_routes() here: it locks smoltcp's iface mutex and can
        // deadlock with TX/RX/poll paths. /proc/net/arp only needs tracked routes.
        let routes = self.routes.lock();
        let _ = writeln!(s, "IP address       HW type     Flags       HW address            Mask     Device");
        for route in routes.iter() {
            if let Some(IpAddress::Ipv4(gw)) = route.gateway {
                let _ = writeln!(
                    s,
                    "{:<15}  0x1         0x2         52:54:00:12:34:56     *        {}",
                    gw,
                    self.name
                );
            }
        }
        s
    }
}

// ---------------------------------------------------------------------------
// smoltcp Device impl
// ---------------------------------------------------------------------------
pub struct E1000eRxToken {
    data: Vec<u8>,
}

pub struct E1000eTxToken(E1000eDriver);

impl phy::Device<'_> for E1000eDriver {
    type RxToken = E1000eRxToken;
    type TxToken = E1000eTxToken;

    fn receive(&mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        let mut hw = self.hw.lock();
        if let Some(pkt) = hw.receive() {
            // NOTE: net_dispatch_packet is intentionally NOT called here.
            // smoltcp owns this packet via the RxToken; calling dispatch would
            // send the same bytes to a raw-packet callback before smoltcp has
            // parsed/acknowledged them, causing DHCP/ARP processing races.
            // Raw-socket dispatch (if needed) should happen after smoltcp
            // processes the frame inside RxToken::consume.
            Some((
                E1000eRxToken { data: pkt },
                E1000eTxToken(self.clone()),
            ))
        } else {
            None
        }
    }
    fn transmit(&mut self) -> Option<Self::TxToken> {
        if self.hw.lock().can_send() {
            Some(E1000eTxToken(self.clone()))
        } else {
            None
        }
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1536;
        caps.max_burst_size = Some(64);
        caps
    }
}

impl phy::RxToken for E1000eRxToken {
    fn consume<R, F>(self, _ts: Instant, f: F) -> SmolResult<R>
    where
        F: FnOnce(&mut [u8]) -> SmolResult<R>,
    {
        let mut data = self.data;
        // Dispatch the raw Ethernet frame to AF_PACKET sockets (udhcpc, tcpdump, ping…)
        // BEFORE smoltcp processes it. smoltcp only mutates the slice in-place for
        // checksums on some TX paths; RX frames are never modified by smoltcp 0.8.
        // Dispatching here (not in Device::receive) ensures the bytes are available
        // to raw-socket readers regardless of whether smoltcp accepts or drops the frame.
        super::net_dispatch_packet(&data);
        f(&mut data)
    }
}

impl phy::TxToken for E1000eTxToken {
    fn consume<R, F>(self, _ts: Instant, len: usize, f: F) -> SmolResult<R>
    where
        F: FnOnce(&mut [u8]) -> SmolResult<R>,
    {
        let mut buf = vec![0u8; len];
        // NOTE: do NOT call net_dispatch_packet here. The buffer is empty at this point
        // (smoltcp fills it via the closure below). Dispatching it as a received packet
        // would inject garbage frames into AF_PACKET sockets.
        let result = f(&mut buf)?;
        let mut hw = self.0.hw.lock();
        hw.send(&buf).map_err(|_| smoltcp::Error::Exhausted)?;
        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Public init — called from pci.rs
// ---------------------------------------------------------------------------
pub fn init(
    name: String,
    pci: &PCIDevice,
    irq: usize,
    vaddr: usize,  // MMIO virtual base
    _index: usize, // card index for IP suffix
) -> DeviceResult<E1000eInterface> {
    info!(
        "[e1000e] probing {} at vaddr={:#x} irq={}",
        name, vaddr, irq
    );

    // Allocate DMA rings
    let rx_ring = DmaRegion::alloc(NUM_RX * size_of::<RxDesc>()).ok_or(DeviceError::DmaError)?;
    let tx_ring = DmaRegion::alloc(NUM_TX * size_of::<TxDesc>()).ok_or(DeviceError::DmaError)?;

    let mut rx_bufs = Vec::with_capacity(NUM_RX);
    let mut tx_bufs = Vec::with_capacity(NUM_TX);

    for _ in 0..NUM_RX {
        rx_bufs.push(DmaRegion::alloc_uninit(BUF_SIZE).ok_or(DeviceError::DmaError)?);
    }
    for _ in 0..NUM_TX {
        tx_bufs.push(DmaRegion::alloc(BUF_SIZE).ok_or(DeviceError::DmaError)?);
    }

    let mut hw = E1000eHw {
        base: vaddr,
        pci_loc: pci.loc,
        device_id: pci.id.device_id,
        mac: [0u8; 6], // Read from hardware during reset
        rx_ring,
        rx_bufs,
        rx_tail: 0,
        tx_ring,
        tx_bufs,
        tx_tail: 0,
        phy_addr: 1, // Default to 1, updated during probe
        stats: NetStats::default(),
        last_hw_rx_packets: 0,
        rx_diag_counter: 0,
    };

    unsafe {
        hw.reset_and_init()?;
    }

    let mac_bytes = hw.mac;
    crate::klog_info!(
        "e1000e: {} registered tag={} profile={} MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} PCI {:#x}:{:#x}\n",
        name,
        E1000E_DRIVER_TAG,
        e1000e_profile(),
        mac_bytes[0],
        mac_bytes[1],
        mac_bytes[2],
        mac_bytes[3],
        mac_bytes[4],
        mac_bytes[5],
        pci.id.vendor_id,
        pci.id.device_id
    );
    let hw_arc = Arc::new(Mutex::new(hw));
    let driver = E1000eDriver { hw: hw_arc.clone() };

    let ethernet_addr = EthernetAddress::from_bytes(&mac_bytes);
    // Start with unspecified address (0.0.0.0/0) so smoltcp accepts all ARP
    // probes and DHCP can assign the real address without routing conflicts.
    // A /24 here would make smoltcp reject ARP for IPs outside that subnet.
    let ip_addrs = [IpCidr::new(IpAddress::v4(0, 0, 0, 0), 0)];
    let default_v4_gw = Ipv4Address::new(0, 0, 0, 0);
    static mut ROUTES_STORAGE: [Option<(IpCidr, Route)>; 4] = [None; 4];
    let mut routes = unsafe { Routes::new(&mut ROUTES_STORAGE[..]) };
    routes.add_default_ipv4_route(default_v4_gw).unwrap();
    let neighbor_cache = NeighborCache::new(BTreeMap::new());

    let iface = InterfaceBuilder::new(driver.clone())
        .ethernet_addr(ethernet_addr)
        .neighbor_cache(neighbor_cache)
        .ip_addrs(ip_addrs)
        .routes(routes)
        .finalize();


    let link_up_seen = Arc::new(core::sync::atomic::AtomicBool::new(
        unsafe { mmio_read(vaddr, E1000E_STATUS) & STATUS_LU != 0 },
    ));
    let e1000e_iface = E1000eInterface {
        iface: Arc::new(Mutex::new(iface)),
        driver,
        name,
        irq,
        base: vaddr,
        poll_pending: Arc::new(core::sync::atomic::AtomicBool::new(false)),
        link_up_seen,
        routes: Arc::new(Mutex::new(vec![RouteInfo {
            dst: IpCidr::new(IpAddress::v4(0, 0, 0, 0), 0),
            gateway: Some(IpAddress::Ipv4(default_v4_gw)),
        }])),
    };

    Ok(e1000e_iface)
}

pub struct E1000eDriverPci;

impl PciDriver for E1000eDriverPci {
    fn name(&self) -> &str {
        "e1000e"
    }

    fn matched(&self, vendor_id: u16, device_id: u16) -> bool {
        if vendor_id != 0x8086 {
            return false;
        }
        matches!(
            device_id,
            // 82574L, 82583V
            0x10d3 | 0x10f5 | 0x150c |
            // I217, I218
            0x153a | 0x153b | 0x155a | 0x1559 | 0x15a0..=0x15a3 |
            // I219
            0x156f..=0x1570 | 0x15b7..=0x15be | 0x15d6..=0x15d8 | 0x15e3 | 0x0d4c..=0x0d4f | 
            0x15f4..=0x15fc | 0x1a1c..=0x1a1f | 0x0dc5..=0x0dc8 | 0x550a..=0x5511 | 
            0x57a0..=0x57a1 | 0x57b3..=0x57ba |
            // I210/I211 (sometimes handled by e1000e)
            0x1533 | 0x1539 | 0x157b | 0x157c
        )
    }

    fn init(&self, dev: &PCIDevice, mapper: &Option<Arc<dyn IoMapper>>, irq: Option<usize>) -> DeviceResult<Device> {
        crate::klog_info!(
            "e1000e: probing PCI {:#x}:{:#x} tag={} profile={}\n",
            dev.id.vendor_id,
            dev.id.device_id,
            E1000E_DRIVER_TAG,
            e1000e_profile()
        );
        let bar0_addr = if let Some(BAR::Memory(a, _, _, _)) = dev.bars[0] {
            a as usize
        } else {
            return Err(DeviceError::IoError);
        };
        
        if let Some(m) = mapper {
            m.query_or_map(bar0_addr, 128 * 1024);
        }
        
        let vaddr = crate::net::phys_to_virt(bar0_addr);
        let name = alloc::format!("eth{}", dev.loc.bus);
        
        // Ensure BUS MASTER is enabled in PCI command register
        unsafe {
            let mut cmd = PCI_ACCESS.read16(&PortOpsImpl, dev.loc, 0x04);
            cmd |= 0x0004; // Bus Master
            cmd |= 0x0002; // Memory Space
            PCI_ACCESS.write16(&PortOpsImpl, dev.loc, 0x04, cmd);
        }

        let vector = irq.map(|idx| idx + 32).unwrap_or(0);
        let iface = init(name, dev, vector, vaddr, 0)?;
        let iface_arc = Arc::new(iface);
        if vector != 0 {
            crate::net::pci_note_pending_msi(vector, iface_arc.clone());
        }
        Ok(Device::Net(iface_arc))
    }
}
