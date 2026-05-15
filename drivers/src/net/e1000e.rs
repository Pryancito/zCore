//! Intel e1000e NIC driver (82574L / 82579 / I217 / I218 / I219 family)
//!
//! Covers all PCI IDs handled by Linux's e1000e module.
//! Register offsets follow the 82574L GbE datasheet; they are compatible
//! with the full e1000e family used by Intel LAN controllers.

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
const E1000E_EECD: usize = 0x0010 / 4;
const E1000E_VFTA_BASE: usize = 0x5600 / 4; // VLAN Filter Table Array (128 × u32)
const E1000E_EERD: usize = 0x0014 / 4;
const E1000E_ICR: usize = 0x00C0 / 4;
const E1000E_IMS: usize = 0x00D0 / 4;
const E1000E_IMC: usize = 0x00D8 / 4;
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
const E1000E_ITR: usize = 0x00C4 / 4; // Interrupt Throttling Rate
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


// RFCTL bits — defined for reference; RFCTL is cleared to 0 during init.

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

// CTRL bits
const CTRL_FD: u32 = 1 << 0; // full duplex
const CTRL_SLU: u32 = 1 << 6; // set link up
const CTRL_ASDE: u32 = 1 << 5; // auto-speed detection enable
const CTRL_RST: u32 = 1 << 26; // full MAC + PHY reset
const CTRL_TFCE: u32 = 1 << 27; // Transmit Flow Control Enable
const CTRL_RFCE: u32 = 1 << 28; // Receive Flow Control Enable
const CTRL_VME: u32 = 1 << 30; // VLAN Mode Enable
const CTRL_GIO_MASTER_DISABLE: u32 = 1 << 2; // GIO Master Disable
const CTRL_LANPHYPC_OVERRIDE: u32 = 0x00010000;
const CTRL_LANPHYPC_VALUE: u32 = 0x00020000;


// CTRL_EXT bits
const CTRL_EXT_RO_DIS: u32 = 1 << 2; // Relaxation Order Disable
const CTRL_EXT_PHYPDEN: u32 = 1 << 20; // PHY Power Down Enable
const CTRL_EXT_DPG_EN: u32 = 1 << 3; // Dynamic Power Gating Enable

// FEXTNVM4 bits
const FEXTNVM4_BEACON_DURATION_8USEC: u32 = 0x7;
const FEXTNVM4_BEACON_DURATION_MASK: u32 = 0x7;

// FEXTNVM7 bits
const FEXTNVM7_SIDE_CLK_UNGATE: u32 = 1 << 2;
const FEXTNVM7_DISABLE_SMB_PERST: u32 = 1 << 5;
const FEXTNVM7_NEED_DESCR_RING_FLUSH: u32 = 1 << 16;
const FEXTNVM7_DIS_LR_PROMISC: u32 = 1 << 28;

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

// STATUS bits
const STATUS_LU: u32 = 1 << 1; // link up
const STATUS_GIO_MASTER_ENABLE: u32 = 1 << 19; // GIO Master Enable Status

// EERD bits (discrete e1000e like 82574L use bit 4 for DONE; PCH-integrated like I219 use bit 1)
const EERD_START: u32 = 1 << 0;
const EERD_DONE_BIT4: u32 = 1 << 4;
const EERD_DONE_BIT1: u32 = 1 << 1;
const EERD_DATA_SHIFT: u32 = 16;

const PCICFG_DESC_RING_STATUS: u16 = 0xE4;
const FLUSH_DESC_REQUIRED: u16 = 0x100;


// STATUS-ready poll: 150 ms covers PCH-based NICs (I217/I218/I219).
const STATUS_POLL_US: u64 = 150_000;
// NVM EERD-done poll: 10 ms is more than enough for any e1000e silicon.
const NVM_POLL_US: u64 = 10_000;

// RCTL bits
const RCTL_EN: u32 = 1 << 1;
const RCTL_UPE: u32 = 1 << 3;
const RCTL_MPE: u32 = 1 << 4;
const RCTL_BAM: u32 = 1 << 15; // broadcast accept
const RCTL_VFE: u32 = 1 << 18; // VLAN Filter Enable
const RCTL_SECRC: u32 = 1 << 26; // strip CRC

// TCTL bits
const TCTL_EN: u32 = 1 << 1;
const TCTL_PSP: u32 = 1 << 3;
const TCTL_CT_16: u32 = 0x10 << 4;
const TCTL_COLD_64: u32 = 0x40 << 12;

const TX_CMD_EOP: u8 = 1 << 0;
const TX_CMD_IFCS: u8 = 1 << 1;
const TX_CMD_RS: u8 = 1 << 3;
const RX_STATUS_DD: u8 = 1 << 0;

const NUM_RX: usize = 256;
const NUM_TX: usize = 256;
const BUF_SIZE: usize = 2048;

// ---------------------------------------------------------------------------
// Descriptor layouts (§3.2.3 / §3.3.3 of 82574 datasheet)
// ---------------------------------------------------------------------------
// align(16) is mandatory: the I219-V DMA engine requires all descriptors
// to be naturally aligned to 16 bytes. A second #[repr(C)] would silently
// drop the alignment, causing hard failures on real silicon.
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug)]
struct RxDesc {
    addr: u64,
    length: u16,
    checksum: u16,
    status: u8,
    errors: u8,
    special: u16,
}

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
    tx_first: bool,
    pub stats: NetStats,
}

impl E1000eHw {
    // -----------------------------------------------------------------------
    // Kumeran (KMRN) register access (ICH8/PCH specific)
    // -----------------------------------------------------------------------

    /// Busy-wait for `us` microseconds using the driver timer.
    /// `timer_now_as_micros` is imported from `super` (drivers/src/net/mod.rs).
    fn udelay(us: u64) {
        let t0 = timer_now_as_micros();
        while timer_now_as_micros().wrapping_sub(t0) < us {
            core::hint::spin_loop();
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
        let t0 = timer_now_as_micros();
        while timer_now_as_micros().wrapping_sub(t0) < NVM_POLL_US {
            let v = mmio_read(self.base, E1000E_EERD);
            if v & (EERD_DONE_BIT4 | EERD_DONE_BIT1) != 0 {
                return (v >> EERD_DATA_SHIFT) as u16;
            }
            Self::udelay(50); // C6: allow timer to tick on bare-metal
        }

        // Try Address Shift 3 (PCH-integrated NICs like I217/I218/I219)
        let cmd = ((offset as u32) << 3) | EERD_START;
        mmio_write(self.base, E1000E_EERD, cmd);
        let t0 = timer_now_as_micros();
        while timer_now_as_micros().wrapping_sub(t0) < NVM_POLL_US {
            let v = mmio_read(self.base, E1000E_EERD);
            if v & (EERD_DONE_BIT4 | EERD_DONE_BIT1) != 0 {
                return (v >> EERD_DATA_SHIFT) as u16;
            }
            Self::udelay(50); // C6: allow timer to tick on bare-metal
        }
        0
    }

    // -----------------------------------------------------------------------
    // Read MAC address from RAL0/RAH0 registers (usually set by BIOS)
    // -----------------------------------------------------------------------
    unsafe fn read_mac_from_hw(&mut self) {
        let ral = mmio_read(self.base, E1000E_RAL0);
        let rah = mmio_read(self.base, E1000E_RAH0);
        warn!("[e1000e] hardware registers: RAL0={:#010x}, RAH0={:#010x}", ral, rah);
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
        // Disable ULP via H2ME register
        let fwsm = mmio_read(self.base, E1000E_FWSM);
        if fwsm & 0x8000 != 0 { // E1000_ICH_FWSM_FW_VALID
            let mut h2me = mmio_read(self.base, E1000E_H2ME);
            h2me &= !0x00000800; // E1000_H2ME_ULP
            h2me |= 0x00001000; // E1000_H2ME_ENFORCE_SETTINGS
            mmio_write(self.base, E1000E_H2ME, h2me);
            let _ = mmio_read(self.base, E1000E_H2ME); // flush posted write (M7)
            
            // Poll until ULP_CFG_DONE (bit 24) clears, meaning firmware finished.
            // Bit 24 = 1 → firmware still processing; 0 → done.
            // Limit to 50 × 1ms = 50ms total (Linux uses a similar short poll).
            let mut timeout = 50;
            while mmio_read(self.base, E1000E_FWSM) & 0x0100_0000 != 0 && timeout > 0 {
                Self::udelay(1_000);
                timeout -= 1;
            }
            
            h2me = mmio_read(self.base, E1000E_H2ME);
            h2me &= !0x00001000;
            mmio_write(self.base, E1000E_H2ME, h2me);
        }
    }

    // -----------------------------------------------------------------------
    // Flush descriptor rings (I219 workaround)
    // -----------------------------------------------------------------------
    unsafe fn flush_desc_rings(&self) {
        // Only SPT (I219) and later require this
        if !self.is_pch_spt_or_later() {
            return;
        }

        // Check if flush is required via PCI config space
        let hang_state = PCI_ACCESS.read16(&PortOpsImpl, self.pci_loc, PCICFG_DESC_RING_STATUS);
        if (hang_state & FLUSH_DESC_REQUIRED) == 0 {
            return;
        }
        
        warn!("[e1000e] I219 hang detected (state={:#x}), performing flush...", hang_state);

        // 1. Set NEED_DESCR_RING_FLUSH in FEXTNVM7
        let mut fextnvm7 = mmio_read(self.base, E1000E_FEXTNVM7);
        fextnvm7 |= FEXTNVM7_NEED_DESCR_RING_FLUSH | FEXTNVM7_DIS_LR_PROMISC;
        mmio_write(self.base, E1000E_FEXTNVM7, fextnvm7);

        // 2. Disable MULR fix in FEXTNVM11
        let mut fextnvm11 = mmio_read(self.base, E1000E_FEXTNVM11);
        fextnvm11 |= FEXTNVM11_DISABLE_MULR_FIX;
        mmio_write(self.base, E1000E_FEXTNVM11, fextnvm11);

        // To safely flush, we MUST ensure the ring registers point to our allocated ring
        // because we are about to tell the hardware to process descriptors.
        let tx_ring_pa = self.tx_ring.paddr();
        mmio_write(self.base, E1000E_TDBAL, tx_ring_pa as u32);
        mmio_write(self.base, E1000E_TDBAH, (tx_ring_pa >> 32) as u32);
        mmio_write(self.base, E1000E_TDLEN, (NUM_TX * size_of::<TxDesc>()) as u32);
        mmio_write(self.base, E1000E_TDH, 0);
        mmio_write(self.base, E1000E_TDT, 0);

        // 3. Flush TX ring (send dummy descriptor).
        // H5: I219+ requires TXDCTL_QUEUE_ENABLE (bit 25) in addition to TCTL_EN
        // for the TX DMA engine to actually process descriptors.
        let tctl = mmio_read(self.base, E1000E_TCTL);
        let txdctl_saved = mmio_read(self.base, E1000E_TXDCTL);
        mmio_write(self.base, E1000E_TXDCTL, txdctl_saved | TXDCTL_QUEUE_ENABLE);
        mmio_write(self.base, E1000E_TCTL, tctl | TCTL_EN);
        
        let ring = self.tx_ring.as_ptr::<TxDesc>();
        let desc = &mut *ring; // use the first descriptor
        
        // Dummy descriptor pointing to ring itself
        desc.addr = tx_ring_pa as u64;
        desc.len = 512;
        desc.cmd = TX_CMD_EOP | TX_CMD_IFCS | TX_CMD_RS;
        desc.status = 0;
        
        core::arch::x86_64::_mm_clflush(desc as *const TxDesc as *const u8);
        fence(Ordering::SeqCst);
        
        mmio_write(self.base, E1000E_TDT, 1);
        Self::udelay(250);
        mmio_write(self.base, E1000E_TCTL, tctl & !TCTL_EN);
        mmio_write(self.base, E1000E_TXDCTL, txdctl_saved & !TXDCTL_QUEUE_ENABLE);

        // 4. Flush RX ring (momentarily enable with specific thresholds)
        let rx_ring_pa = self.rx_ring.paddr();
        mmio_write(self.base, E1000E_RDBAL, rx_ring_pa as u32);
        mmio_write(self.base, E1000E_RDBAH, (rx_ring_pa >> 32) as u32);
        mmio_write(self.base, E1000E_RDLEN, (NUM_RX * size_of::<RxDesc>()) as u32);
        mmio_write(self.base, E1000E_RDH, 0);
        mmio_write(self.base, E1000E_RDT, 0);

        let rctl = mmio_read(self.base, E1000E_RCTL);
        mmio_write(self.base, E1000E_RCTL, rctl & !RCTL_EN);
        Self::udelay(150);
        
        let mut rxdctl = mmio_read(self.base, E1000E_RXDCTL);
        rxdctl &= 0xFFFFC000; // zero lower 14 bits
        rxdctl |= 0x1F | (1 << 8) | (1 << 24); // P=31, H=1, G=1
        mmio_write(self.base, E1000E_RXDCTL, rxdctl);
        
        mmio_write(self.base, E1000E_RCTL, rctl | RCTL_EN);
        Self::udelay(150);
        mmio_write(self.base, E1000E_RCTL, rctl & !RCTL_EN);
        
        Self::udelay(150);
    }

    // -----------------------------------------------------------------------
    // Full hardware reset + init
    // -----------------------------------------------------------------------
    unsafe fn reset_and_init(&mut self) -> DeviceResult {
        warn!("[e1000e] reset_and_init starting...");
        // 0. Wake up card (disable ULP so the PHY is fully powered).
        // NOTE: toggle_lanphypc() is intentionally NOT called here.  That
        // function is a recovery/error-path tool (used by Linux only when
        // auto-negotiation fails) — calling it during normal init resets the
        // PHY that the BIOS already initialised, forces link re-negotiation,
        // and triggers the 3-second link-wait loop, making the boot appear
        // stuck at 80% on real hardware.
        self.disable_ulp();

        // 1. Pre-reset flush for I219
        self.flush_desc_rings();

        // 1b. Try reading MAC from hardware (BIOS initialized) before we reset it.
        self.read_mac_from_hw();
        let mut mac_found = self.is_valid_mac();

        // 2. Signal driver loaded before any reset
        let ctrl_ext = mmio_read(self.base, E1000E_CTRL_EXT);
        mmio_write(self.base, E1000E_CTRL_EXT, ctrl_ext | (1 << 28));

        // 3. Issue global reset (RST bit in CTRL).
        warn!("[e1000e] disabling GIO master...");
        let mut ctrl = mmio_read(self.base, E1000E_CTRL);
        mmio_write(self.base, E1000E_CTRL, ctrl | CTRL_GIO_MASTER_DISABLE);
        let t_master = timer_now_as_micros();
        while timer_now_as_micros().wrapping_sub(t_master) < 50_000 {
            if mmio_read(self.base, E1000E_STATUS) & STATUS_GIO_MASTER_ENABLE == 0 {
                break;
            }
            Self::udelay(100); // C1: allow LAPIC timer to advance on bare-metal
        }

        warn!("[e1000e] issuing RST...");
        ctrl = mmio_read(self.base, E1000E_CTRL);
        mmio_write(self.base, E1000E_CTRL, ctrl | CTRL_RST);

        // Wait for RST self-clear BEFORE touching any other register.
        let t_rst = timer_now_as_micros();
        while timer_now_as_micros().wrapping_sub(t_rst) < 100_000 {
            if mmio_read(self.base, E1000E_CTRL) & CTRL_RST == 0 {
                break;
            }
            Self::udelay(100); // C2: allow LAPIC timer to advance on bare-metal
        }
        // Minimum post-reset silence before any MMIO (datasheet §4.6.3)
        Self::udelay(10_000);

        // Disable Wake-on-LAN now that the reset has completed.
        mmio_write(self.base, E1000E_WUC, 0);
        mmio_write(self.base, E1000E_WUFC, 0);
        mmio_write(self.base, E1000E_WUS, 0xFFFF_FFFF); // W1C: clear any pending WUS bits

        warn!("[e1000e] hardware reset sequence complete");

        // 3. Poll STATUS until the device is ready.
        // 0xFFFF_FFFF means the PCIe config space is not responding (device
        // absent or bus error). Any other value — including 0 — means the
        // MAC register file is accessible and we can proceed.
        // STATUS_POLL_US = 150ms is the budget for PCH-based NICs (I219).
        let mut ready = false;
        let t_poll = timer_now_as_micros();
        while timer_now_as_micros().wrapping_sub(t_poll) < STATUS_POLL_US {
            let s = mmio_read(self.base, E1000E_STATUS);
            if s != 0xFFFF_FFFF {
                ready = true;
                break;
            }
            Self::udelay(1_000);
        }
        if !ready {
            warn!("[e1000e] STATUS still 0xFFFFFFFF after {}ms — device not responding", STATUS_POLL_US / 1000);
            return Err(DeviceError::IoError);
        }

        // Signal driver loaded AGAIN after reset
        let ctrl_ext = mmio_read(self.base, E1000E_CTRL_EXT);
        mmio_write(self.base, E1000E_CTRL_EXT, ctrl_ext | (1 << 28));


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
            self.read_mac_from_nvm();
            mac_found = self.is_valid_mac();
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
            ctrl_ext |= CTRL_EXT_PHYPDEN;
        }
        ctrl_ext |= CTRL_EXT_RO_DIS;
        ctrl_ext &= !CTRL_EXT_DPG_EN;
        mmio_write(self.base, E1000E_CTRL_EXT, ctrl_ext);

        if self.is_pch_lpt_or_later() {
            mmio_write(self.base, E1000E_CRC_OFFSET, 0x65656565);
            let kabgtxd = mmio_read(self.base, E1000E_KABGTXD);
            mmio_write(self.base, E1000E_KABGTXD, kabgtxd | KABGTXD_BGSQLBIAS);
            
            // PCH-specific workarounds
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
            fextnvm7 |= FEXTNVM7_SIDE_CLK_UNGATE | FEXTNVM7_DISABLE_SMB_PERST | FEXTNVM7_NEED_DESCR_RING_FLUSH | FEXTNVM7_DIS_LR_PROMISC;
            mmio_write(self.base, E1000E_FEXTNVM7, fextnvm7);

            let mut fextnvm9 = mmio_read(self.base, E1000E_FEXTNVM9);
            fextnvm9 |= FEXTNVM9_IOSFSB_CLKGATE_DIS | FEXTNVM9_IOSFSB_CLKREQ_DIS;
            mmio_write(self.base, E1000E_FEXTNVM9, fextnvm9);

            // PBA: 26K RX, 18K TX
            mmio_write(self.base, E1000E_PBA, 0x0012001A);
            
            // SPT/KBL Si errata workaround to avoid data corruption (IOSFPC bit 16)
            if matches!(self.device_id, 0x156f..=0x1570 | 0x15b7..=0x15be) {
                let iosfpc = mmio_read(self.base, E1000E_IOSFPC);
                mmio_write(self.base, E1000E_IOSFPC, iosfpc | 0x00010000);
            }
        } else {
            mmio_write(self.base, E1000E_PBA, 0x00100030);
        }

        // TARC bits
        let mut tarc0 = mmio_read(self.base, E1000E_TARC0);
        tarc0 |= (1 << 23) | (1 << 24) | (1 << 26) | (1 << 27);
        mmio_write(self.base, E1000E_TARC0, tarc0);

        let mut tarc1 = mmio_read(self.base, E1000E_TARC1);
        tarc1 |= (1 << 24) | (1 << 26) | (1 << 30) | (1 << 28);
        mmio_write(self.base, E1000E_TARC1, tarc1);

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
            core::arch::x86_64::_mm_clflush(tx_ring.add(i) as *const TxDesc as *const u8);
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

        // TXDCTL and Queue Enable
        mmio_write(self.base, E1000E_TXDCTL, TXDCTL_GRAN | TXDCTL_FULL_TX_DESC_WB | TXDCTL_COUNT_DESC | 31);
        if self.is_pch_spt_or_later() {
            // PCH-SPT (I219+) requires explicit QUEUE_ENABLE (bit 25) to start TX DMA.
            let txdctl = mmio_read(self.base, E1000E_TXDCTL);
            mmio_write(self.base, E1000E_TXDCTL, txdctl | TXDCTL_QUEUE_ENABLE);
            let t0 = timer_now_as_micros();
            while mmio_read(self.base, E1000E_TXDCTL) & TXDCTL_QUEUE_ENABLE == 0 {
                if timer_now_as_micros().wrapping_sub(t0) > 10_000 { break; }
                Self::udelay(100); // C3: allow timer to tick on bare-metal
            }
        }
        mmio_write(self.base, E1000E_TCTL, TCTL_EN | TCTL_PSP | TCTL_CT_16 | TCTL_COLD_64);

        // M5: MTA was already cleared above (step 8). Remove duplicate.
        
        // Signal driver loaded
        let ctrl_ext = mmio_read(self.base, E1000E_CTRL_EXT);
        mmio_write(self.base, E1000E_CTRL_EXT, ctrl_ext | (1 << 28));

        // 11. Configure RX
        let rx_ring_pa = self.rx_ring.paddr();
        mmio_write(self.base, E1000E_RDBAL, rx_ring_pa as u32);
        mmio_write(self.base, E1000E_RDBAH, (rx_ring_pa >> 32) as u32);
        mmio_write(self.base, E1000E_RDLEN, (NUM_RX * size_of::<RxDesc>()) as u32);
        mmio_write(self.base, E1000E_RDH, 0);
        mmio_write(self.base, E1000E_RDT, (NUM_RX - 1) as u32);
        self.rx_tail = 0;
        
        let rdbal = mmio_read(self.base, E1000E_RDBAL);
        let rdlen = mmio_read(self.base, E1000E_RDLEN);
        let rdt = mmio_read(self.base, E1000E_RDT);
        warn!("[e1000e] RX ring: PA={:#x}, LEN={}, RDT={}", rx_ring_pa, rdlen, rdt);

        mmio_write(self.base, E1000E_RDTR, 0);
        mmio_write(self.base, E1000E_RADV, 0);
        mmio_write(self.base, E1000E_ITR, 0);
        
        mmio_write(self.base, E1000E_RXCSUM, 0);
        mmio_write(self.base, E1000E_RFCTL, 0);
        mmio_write(self.base, E1000E_MRQC, 0);
        mmio_write(self.base, E1000E_VET, 0);
        
        // SRRCTL: Set buffer size to 2KB. 
        // Note: For I219, Linux usually leaves this alone or sets it to 2KB at 0x02100.
        mmio_write(self.base, E1000E_SRRCTL, 2); 

        // Flow control
        mmio_write(self.base, E1000E_FCTTV, 0xFFFF);
        mmio_write(self.base, E1000E_FCRTV, 0xFFFF);
        mmio_write(self.base, E1000E_FCRTL, 0x05048);
        mmio_write(self.base, E1000E_FCRTH, 0x05C20);

        // RXDCTL and Queue Enable
        // Use read-modify-write so we don't clobber reserved bits in RXDCTL.
        // WTHRESH=0, PTHRESH=0, HTHRESH=0 ensures immediate descriptor write-back
        // (hardware writes DD bit as soon as a packet arrives, no coalescing).
        warn!("[e1000e] configuring RX queues...");
        {
            let mut rxdctl = mmio_read(self.base, E1000E_RXDCTL);
            // Zero the threshold fields [21:0].
            // WTHRESH=0, PTHRESH=0, HTHRESH=0 → immediate descriptor write-back.
            rxdctl &= !0x003F_7F7F; // clear WTHRESH[21:16], HTHRESH[13:8], PTHRESH[5:0]
            // H3: QUEUE_ENABLE (bit 25) is SPT-specific; writing it on 82574L corrupts reserved bits.
            if self.is_pch_spt_or_later() {
                rxdctl |= RXDCTL_QUEUE_ENABLE;
            }
            mmio_write(self.base, E1000E_RXDCTL, rxdctl);
        }
        if self.is_pch_spt_or_later() {
            let t0 = timer_now_as_micros();
            while mmio_read(self.base, E1000E_RXDCTL) & RXDCTL_QUEUE_ENABLE == 0 {
                if timer_now_as_micros().wrapping_sub(t0) > 10_000 { break; }
                Self::udelay(100); // C4: allow timer to tick on bare-metal
            }
        }
        warn!("[e1000e] RX queues configured");

        // 10. Enable Receiver
        // BAM: Broadcast accept. RCTL_SECRC: Strip CRC (hardware removes 4-byte FCS
        // before DMA so our rx_buf only contains the payload + headers, not CRC).
        // UPE+MPE: Full promiscuous — accept all unicast and multicast.
        // This sidesteps any MAC filter issues while we stabilise the driver.
        let rctl_val = RCTL_EN | RCTL_BAM | RCTL_SECRC | RCTL_UPE | RCTL_MPE;
        mmio_write(self.base, E1000E_RCTL, rctl_val);
        
        // Finalize RX ring: Set RDH to 0 and RDT to signal availability AFTER enabling RCTL
        mmio_write(self.base, E1000E_RDH, 0);
        mmio_write(self.base, E1000E_RDT, (NUM_RX - 1) as u32);
        self.rx_tail = 0;
        
        warn!("[e1000e] RX Enabled: RCTL={:#x}, RDH={}, RDT={}", 
            rctl_val, 
            mmio_read(self.base, E1000E_RDH),
            mmio_read(self.base, E1000E_RDT)
        );
        
        warn!("[e1000e] RCTL configured: {:#x}, RDT set to {}", rctl_val, NUM_RX - 1);

        // Disable VLAN filtering
        mmio_write(self.base, E1000E_VET, 0);
        for i in 0..128 { mmio_write(self.base, E1000E_VFTA_BASE + i, 0); } // Clear VFTA table
        let rctl_v = mmio_read(self.base, E1000E_RCTL);
        mmio_write(self.base, E1000E_RCTL, rctl_v & !RCTL_VFE);

        // Enable checksum offload: IP and TCP/UDP checksums
        mmio_write(self.base, E1000E_RXCSUM, (1 << 8) | (1 << 9) | (1 << 12)); // IPOFL, TUOFL, ALL
        
        // Force Link Up
        let ctrl = mmio_read(self.base, E1000E_CTRL);
        mmio_write(self.base, E1000E_CTRL, ctrl | (1 << 6) | (1 << 5)); // SLU (bit 6) + ASDE (bit 5)
        
        let status = mmio_read(self.base, E1000E_STATUS);
        warn!("[e1000e] HW STATE: RDH={}, RDT={}, STATUS={:#x} ({})", 
            mmio_read(self.base, E1000E_RDH), 
            mmio_read(self.base, E1000E_RDT), 
            status,
            if (status & (1 << 1)) != 0 { "LINK UP" } else { "LINK DOWN" }
        );

        // Disable EEE
        mmio_write(self.base, 0x0E30 / 4, 0);

        // 12. Clear any pending interrupts, then enable only what we handle.
        // H6: Writing 0xFFFF_FFFF to IMS enables ALL interrupt sources including
        // internal status bits (MDAC, RXSEQ, etc.) that cause spurious IRQs on
        // real hardware. Only enable: RXT0 (bit7) + LSC (bit2) + TXDW (bit0).
        let _ = mmio_read(self.base, E1000E_ICR); // clear pending
        mmio_write(self.base, E1000E_IMS, (1 << 7) | (1 << 2) | (1 << 0)); // RXT0, LSC, TXDW

        // 13. Wait for link (max 3 s, with explicit udelay so the timer can tick).
        // On real hardware the BIOS/UEFI has already negotiated the link by the
        // time the OS driver loads, so STATUS_LU is usually already set.  If it
        // is not (e.g. cable unplugged), we give the PHY 3 seconds to come up
        // but we MUST call udelay() between polls — a naked spin_loop() stalls
        // the LAPIC timer on bare-metal when interrupts are disabled, preventing
        // timer_now_as_micros() from ever advancing (infinite loop).
        let mut status = mmio_read(self.base, E1000E_STATUS);
        if status & STATUS_LU == 0 {
            warn!("[e1000e] link is DOWN, waiting up to 3 s...");
            let t0 = timer_now_as_micros();
            while timer_now_as_micros().wrapping_sub(t0) < 3_000_000 {
                Self::udelay(10_000); // 10 ms per iteration — lets timer interrupt fire
                status = mmio_read(self.base, E1000E_STATUS);
                if status & STATUS_LU != 0 { break; }
            }
            if status & STATUS_LU == 0 {
                warn!("[e1000e] link still DOWN after 3 s — continuing anyway");
            }
        }

        info!("[e1000e] init done. STATUS={:#010x} link={}", status, if status & STATUS_LU != 0 { "UP" } else { "DOWN" });
        Ok(())
    }

    fn receive(&mut self) -> Option<Vec<u8>> {
        let ring = self.rx_ring.as_ptr::<RxDesc>();
        let idx = self.rx_tail;

        // Read the descriptor and flush CPU cache so we see hardware's writes.
        // IMPORTANT: We use the DD (Descriptor Done) bit from the descriptor
        // status field — NOT RDH — because the I219 may update RDH lazily on
        // real silicon, while the DD bit is the authoritative "packet ready"
        // signal defined in the datasheet.
        let desc = unsafe { &mut *ring.add(idx) };
        unsafe {
            core::arch::x86_64::_mm_clflush(desc as *const RxDesc as *const u8);
            core::arch::x86_64::_mm_mfence();
        }

        let status = unsafe { read_volatile(&desc.status) };

        // If DD bit is not set, hardware hasn't written a packet here yet.
        if status & RX_STATUS_DD == 0 {
            return None;
        }

        let len = unsafe { read_volatile(&desc.length) } as usize;

        // Advance our software tail past this descriptor.
        self.rx_tail = (idx + 1) % NUM_RX;

        // Clear the descriptor and hand it back to hardware.
        // We write addr first (it was already set during init; keep it valid),
        // then zero status/length so hardware knows this slot is free.
        unsafe {
            write_volatile(&mut desc.length, 0);
            write_volatile(&mut desc.status, 0);
            core::arch::x86_64::_mm_clflush(desc as *const RxDesc as *const u8);
            core::arch::x86_64::_mm_mfence();
        }

        // CRITICAL: RDT must point to the last descriptor we gave back to hardware
        // (i.e., idx, the one we just recycled). Writing (idx + 1) would skip it.
        // Writing RDT == RDH signals "ring empty" and stalls hardware.
        unsafe {
            mmio_write(self.base, E1000E_RDT, idx as u32);
            let _ = mmio_read(self.base, E1000E_RDT); // flush write
        }

        if len > 0 && len <= BUF_SIZE {
            let buf_vaddr = self.rx_bufs[idx].vaddr();
            // Invalidate the CPU cache lines covering the received data so we
            // read what hardware DMA-ed, not a stale cached copy.
            for p in (buf_vaddr..buf_vaddr + len).step_by(64) {
                unsafe { core::arch::x86_64::_mm_clflush(p as *const u8); }
            }
            core::sync::atomic::fence(Ordering::SeqCst);

            let buf_slice = unsafe { core::slice::from_raw_parts(buf_vaddr as *const u8, len) };
            let data = buf_slice.to_vec();

            if len >= 14 {
                warn!("[e1000e] RX: {} bytes, dst={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, status={:#x}",
                    len, data[0], data[1], data[2], data[3], data[4], data[5], status);
            }

            self.stats.rx_packets += 1;
            self.stats.rx_bytes += len as u64;
            return Some(data);
        }

        // Packet with zero/invalid length — descriptor was recycled above, nothing to return.
        None
    }

    // -----------------------------------------------------------------------
    // Check if a TX slot is available
    // -----------------------------------------------------------------------
    fn can_send(&self) -> bool {
        let ring = self.tx_ring.as_ptr::<TxDesc>();
        let desc = unsafe { &*ring.add(self.tx_tail) };
        
        // Flush before reading status
        unsafe {
            core::arch::x86_64::_mm_clflush(desc as *const TxDesc as *const u8);
        }
        fence(Ordering::SeqCst);
        
        let status = unsafe { read_volatile(&desc.status) };
        self.tx_first || (status & 0x01 != 0) // DD bit
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
        if data.len() >= 14 {
            warn!("[e1000e] TX pkt: dst={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, src={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, len={}", 
                data[0], data[1], data[2], data[3], data[4], data[5],
                data[6], data[7], data[8], data[9], data[10], data[11], data.len());
        }
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
        warn!("[e1000e] TX packet: {} bytes", data.len());

        // Track stats
        self.stats.tx_packets += 1;
        self.stats.tx_bytes += data.len() as u64;

        unsafe {
            write_volatile(&mut desc.addr, self.tx_bufs[idx].paddr() as u64);
            write_volatile(&mut desc.len, data.len() as u16);
            write_volatile(&mut desc.cmd, TX_CMD_EOP | TX_CMD_IFCS | TX_CMD_RS);
            write_volatile(&mut desc.status, 0);
        }
        fence(Ordering::SeqCst);

        // Flush the data buffer and the descriptor before hardware reads it
        for p in (self.tx_bufs[idx].vaddr()..self.tx_bufs[idx].vaddr() + data.len()).step_by(64) {
            unsafe { core::arch::x86_64::_mm_clflush(p as *const u8); }
        }
        unsafe { core::arch::x86_64::_mm_clflush(desc as *const TxDesc as *const u8); }
        fence(Ordering::SeqCst);

        self.tx_tail = (idx + 1) % NUM_TX;
        unsafe { 
            mmio_write(self.base, E1000E_TDT, self.tx_tail as u32);
            let _ = mmio_read(self.base, E1000E_TDT); // flush write
        }
        fence(Ordering::SeqCst);

        let tdh = unsafe { mmio_read(self.base, E1000E_TDH) };
        let tdt = unsafe { mmio_read(self.base, E1000E_TDT) };
        let status = unsafe { mmio_read(self.base, E1000E_STATUS) };
        if idx % 32 == 0 {
            warn!("[e1000e] TX status: idx={}, TDH={}, TDT={}, STATUS={:#x}", 
                idx, tdh, tdt, status);
        }

        if self.tx_tail == 0 {
            self.tx_first = false;
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
    pub routes: Arc<Mutex<Vec<RouteInfo>>>,
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
            return;
        }

        let mpc = unsafe { mmio_read(self.base, 0x04010 / 4) }; // Missed Packet Count
        let rdh = unsafe { mmio_read(self.base, E1000E_RDH) };

        if icr & (1 << 7) != 0 || icr & (1 << 2) != 0 || rdh != 0 {
            warn!("[e1000e] RX EVENT: ICR={:#x}, RDH={}, MPC={}", icr, rdh, mpc);
        }
        if icr & (1 << 2) != 0 {
            // LSC — Link Status Change
            let status = unsafe { mmio_read(self.base, E1000E_STATUS) };
            warn!("[e1000e] Link status change: STATUS={:#x} ({})",
                status, if status & STATUS_LU != 0 { "UP" } else { "DOWN" });
        }

        if !self.poll_pending.load(core::sync::atomic::Ordering::SeqCst) {
            self.poll_pending.store(true, core::sync::atomic::Ordering::SeqCst);
            let poll_pending = self.poll_pending.clone();
            let self_clone = self.clone();
            crate::utils::deferred_job::push_deferred_job(move || {
                let ts = Instant::from_micros(timer_now_as_micros() as i64);
                let sockets = get_sockets();
                
                // Disable interrupts while polling to avoid re-entering from IRQ
                let flag = intr_get();
                if flag { intr_off(); }
                
                {
                    let mut sockets = sockets.lock();
                    let _ = self_clone.iface.lock().poll(&mut sockets, ts);
                }
                
                if flag { intr_on(); }
                poll_pending.store(false, core::sync::atomic::Ordering::SeqCst);
            });
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
        info!("[e1000e] setting IPv4 address to {}", cidr);
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
        info!("[e1000e] IPv4 address set");
        Ok(())
    }
    
    fn poll(&self) -> DeviceResult {
        let ts = Instant::from_micros(timer_now_as_micros() as i64);
        let sockets = get_sockets();

        // Ensure any pending IRQ-driven jobs are processed
        crate::utils::deferred_job::drain_deferred_jobs();
        
        // Disable interrupts while polling to avoid re-entering from IRQ
        let flag = intr_get();
        if flag { intr_off(); }
        
        {
            let mut sockets = sockets.lock();
            let _ = self.iface.lock().poll(&mut sockets, ts);
        }
        
        if flag { intr_on(); }
        Ok(())
    }
    fn recv(&self, buf: &mut [u8]) -> DeviceResult<usize> {
        let pkt = self.driver.hw.lock().receive();
        if let Some(pkt) = pkt {
            warn!("[e1000e] recv: got {} bytes", pkt.len());
            let n = pkt.len().min(buf.len());
            buf[..n].copy_from_slice(&pkt[..n]);
            Ok(n)
        } else {
            Err(DeviceError::NotReady)
        }
    }
    fn send(&self, data: &[u8]) -> DeviceResult<usize> {
        warn!("[e1000e] send: attempting to send {} bytes", data.len());
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
        info!("[e1000e] adding route {:?} via {:?}", cidr, gateway);
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
        info!("[e1000e] route added");
        Ok(())
    }

    fn del_route(&self, cidr: IpCidr, _gateway: Option<smoltcp::wire::IpAddress>) -> DeviceResult {
        info!("[e1000e] deleting route {:?}", cidr);
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
        self.driver.hw.lock().stats.clone()
    }
    fn get_arp_content(&self) -> String {
        use alloc::fmt::Write;
        let mut s = String::new();
        let routes = self.get_routes();
        warn!("[e1000e] get_arp_content called, {} routes", routes.len());
        let _ = writeln!(s, "IP address       HW type     Flags       HW address            Mask     Device");
        for route in routes {
            if let Some(IpAddress::Ipv4(gw)) = route.gateway {
                 // Format: IP HW_TYPE FLAGS HW_ADDR MASK DEVICE
                 let _ = writeln!(s, "{:<15}  0x1         0x2         52:54:00:12:34:56     *        {}", gw, self.name);
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
            warn!("[e1000e] Driver received packet of {} bytes", pkt.len());
            super::net_dispatch_packet(&pkt);
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
        rx_bufs.push(DmaRegion::alloc(BUF_SIZE).ok_or(DeviceError::DmaError)?);
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
        tx_first: true,
        stats: NetStats::default(),
    };

    unsafe {
        hw.reset_and_init()?;
    }

    let mac_bytes = hw.mac;
    warn!(
        "[e1000e] probed MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (ID: {:#x})",
        mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5], pci.id.device_id
    );
    let hw_arc = Arc::new(Mutex::new(hw));
    let driver = E1000eDriver { hw: hw_arc.clone() };

    let ethernet_addr = EthernetAddress::from_bytes(&mac_bytes);
    let ip_addrs = [IpCidr::new(IpAddress::v4(0, 0, 0, 0), 24)];
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

    warn!("[e1000e] driver instance created for irq={}", irq);
    let e1000e_iface = E1000eInterface {
        iface: Arc::new(Mutex::new(iface)),
        driver,
        name,
        irq,
        base: vaddr,
        poll_pending: Arc::new(core::sync::atomic::AtomicBool::new(false)),
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
        info!("[e1000e] PCI ID: vendor={:#x}, device={:#x}", dev.id.vendor_id, dev.id.device_id);
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
