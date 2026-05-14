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
use pci::{PCIDevice, BAR};
use lock::Mutex;

use super::{timer_now_as_micros, intr_on, intr_off, intr_get};

// ---------------------------------------------------------------------------
// Register offsets (byte addresses / 4 → u32 index)
// ---------------------------------------------------------------------------
const E1000E_CTRL: usize = 0x0000 / 4;
const E1000E_STATUS: usize = 0x0008 / 4;
const E1000E_EECD: usize = 0x0010 / 4;
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

// RFCTL bits
const RFCTL_NFSW_DIS: u32 = 1 << 6;
const RFCTL_NFSR_DIS: u32 = 1 << 7;
const RFCTL_IPV6_EX_DIS: u32 = 1 << 13;
const RFCTL_NEW_IPV6_EXT_DIS: u32 = 1 << 15;

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
const CTRL_MEHE: u32 = 1 << 19; // ME Hardware Enable
const CTRL_SLU: u32 = 1 << 6; // set link up
const CTRL_ASDE: u32 = 1 << 5; // auto-speed detection enable
const CTRL_RST: u32 = 1 << 26; // full MAC + PHY reset
const CTRL_TFCE: u32 = 1 << 27; // Transmit Flow Control Enable
const CTRL_RFCE: u32 = 1 << 28; // Receive Flow Control Enable
const CTRL_VME: u32 = 1 << 30; // VLAN Mode Enable
const CTRL_GIO_MASTER_DISABLE: u32 = 1 << 2; // GIO Master Disable

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
const FEXTNVM7_DIS_LR_PROMISC: u32 = 1 << 28;

// FEXTNVM9 bits
const FEXTNVM9_IOSFSB_CLKGATE_DIS: u32 = 1 << 11;
const FEXTNVM9_IOSFSB_CLKREQ_DIS: u32 = 1 << 12;

// FEXTNVM11 bits
const FEXTNVM11_DISABLE_L1_2: u32 = 0x00000001;
const FEXTNVM11_DISABLE_MULR_FIX: u32 = 1 << 13;

// PBECCSTS bits
const PBECCSTS_ECC_ENABLE: u32 = 1 << 16;

// TXDCTL bits
const TXDCTL_PTHRESH: u32 = 0x3F; // bits 0-5
const TXDCTL_HTHRESH: u32 = 0x3F << 8; // bits 8-13
const TXDCTL_WTHRESH: u32 = 0x3F << 16; // bits 16-21
const TXDCTL_GRAN: u32 = 1 << 24; // 0=cache lines, 1=descriptors
const TXDCTL_FULL_TX_DESC_WB: u32 = 1 << 26;
const TXDCTL_COUNT_DESC: u32 = 1 << 22; // bit 22 must be 1 on some ICH8

// STATUS bits
const STATUS_LU: u32 = 1 << 1; // link up
const STATUS_GIO_MASTER_ENABLE: u32 = 1 << 19; // GIO Master Enable Status

// EERD bits (discrete e1000e like 82574L use bit 4 for DONE; PCH-integrated like I219 use bit 1)
const EERD_START: u32 = 1 << 0;
const EERD_DONE_BIT4: u32 = 1 << 4;
const EERD_DONE_BIT1: u32 = 1 << 1;
const EERD_ADDR_SHIFT: u32 = 2;
const EERD_DATA_SHIFT: u32 = 16;

// Post-reset silence: 10 ms minimum before any MMIO read (datasheet §4.6).
// Measured with the kernel timer so the delay is correct on all CPU speeds.
const POST_RST_US: u64 = 10_000;
// STATUS-ready poll: 150 ms covers PCH-based NICs (I217/I218/I219).
const STATUS_POLL_US: u64 = 150_000;
// NVM EERD-done poll: 10 ms is more than enough for any e1000e silicon.
const NVM_POLL_US: u64 = 10_000;

// RCTL bits
const RCTL_EN: u32 = 1 << 1;
const RCTL_SBP: u32 = 1 << 2;
const RCTL_UPE: u32 = 1 << 3;
const RCTL_MPE: u32 = 1 << 4;
const RCTL_LPE: u32 = 1 << 5;
const RCTL_BAM: u32 = 1 << 15; // broadcast accept
const RCTL_VFE: u32 = 1 << 18; // VLAN Filter Enable
const RCTL_BSIZE_2K: u32 = (0 << 16);
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
const RX_STATUS_EOP: u8 = 1 << 1;

const NUM_RX: usize = 256;
const NUM_TX: usize = 256;
const BUF_SIZE: usize = 2048;

// ---------------------------------------------------------------------------
// Descriptor layouts (§3.2.3 / §3.3.3 of 82574 datasheet)
// ---------------------------------------------------------------------------
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug)]
struct RxDesc {
    // Legacy Rx Descriptor (Write-Back)
    // 0: Buffer Address (Read) / [Reserved] (Write-Back)
    addr: u64,
    // 8: Length (u16)
    length: u16,
    // 10: Checksum (u16)
    checksum: u16,
    // 12: Status (u8)
    status: u8,
    // 13: Errors (u8)
    errors: u8,
    // 14: Special (u16)
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

fn alloc_dma_pages(pages: usize) -> (usize /*virt*/, usize /*phys*/) {
    let phys = unsafe { drivers_dma_alloc(pages) };
    let virt = unsafe { drivers_phys_to_virt(phys) };
    (virt, phys)
}

fn dealloc_dma_pages(virt: usize, pages: usize) {
    let phys = unsafe { drivers_virt_to_phys(virt) };
    unsafe { drivers_dma_dealloc(phys, pages) };
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
#[inline(always)]
unsafe fn mmio_flush(base: usize, reg: usize) {
    // read-back to flush posted write
    let _ = mmio_read(base, reg);
}

// ---------------------------------------------------------------------------
// E1000eHw — raw hardware state
// ---------------------------------------------------------------------------
pub struct E1000eHw {
    base: usize, // MMIO virtual base
    device_id: u16,
    mac: [u8; 6],

    rx_ring: DmaRegion,
    rx_bufs: Vec<DmaRegion>,
    rx_tail: usize,

    tx_ring: DmaRegion,
    tx_bufs: Vec<DmaRegion>,
    tx_tail: usize,
    tx_head_shadow: usize,
    tx_first: bool,
    pub stats: NetStats,
}

impl E1000eHw {
    fn recycle_rx_desc(&mut self, idx: usize, desc: &mut RxDesc) {
        unsafe {
            write_volatile(&mut desc.addr, self.rx_bufs[idx].paddr() as u64);
            write_volatile(&mut desc.length, 0);
            write_volatile(&mut desc.checksum, 0);
            write_volatile(&mut desc.status, 0);
            write_volatile(&mut desc.errors, 0);
            write_volatile(&mut desc.special, 0);
        }

        // Flush the 16-byte descriptor to memory so hardware sees the new addr/status
        unsafe {
            core::arch::x86_64::_mm_clflush(desc as *const RxDesc as *const u8);
        }
        fence(Ordering::SeqCst);
        
        // Update tail pointer. Note: RDT points to the descriptor *after* the last one
        // available to hardware. By setting RDT to the current index, we make this
        // descriptor the new tail, giving hardware ownership of everything up to it.
        self.rx_tail = (idx + 1) % NUM_RX;
        unsafe { 
            mmio_write(self.base, E1000E_RDT, idx as u32);
            let _ = mmio_read(self.base, E1000E_RDT); // flush write
        }
    }

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
            core::hint::spin_loop();
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
            core::hint::spin_loop();
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

    // -----------------------------------------------------------------------
    // Flush descriptor rings (I219 workaround)
    // -----------------------------------------------------------------------
    unsafe fn flush_desc_rings(&self) {
        // Only SPT (I219) and later require this (SPT: 0x156f..=0x1570, 0x15b7..=0x15be, etc.)
        if !matches!(self.device_id, 0x156f..=0x1570 | 0x15b7..=0x15be | 0x15d6..=0x15d8 | 0x15e3 | 0x0d4c..=0x0d4f | 0x15f4..=0x15fc | 0x1a1c..=0x1a1f | 0x0dc5..=0x0dc8 | 0x550a..=0x5511 | 0x57a0..=0x57a1 | 0x57b3..=0x57ba) {
            return;
        }

        // Disable MULR fix in FEXTNVM11
        let mut fextnvm11 = mmio_read(self.base, E1000E_FEXTNVM11);
        fextnvm11 |= FEXTNVM11_DISABLE_MULR_FIX;
        mmio_write(self.base, E1000E_FEXTNVM11, fextnvm11);

        // If TDLEN is non-zero, we might have pending descriptors
        let tdlen = mmio_read(self.base, E1000E_TDLEN);
        if tdlen > 0 {
            // Briefly enable TX to flush
            let tctl = mmio_read(self.base, E1000E_TCTL);
            mmio_write(self.base, E1000E_TCTL, tctl | TCTL_EN);
            let _ = mmio_read(self.base, E1000E_TCTL); // flush
            
            let t_start = timer_now_as_micros();
            while timer_now_as_micros().wrapping_sub(t_start) < 250 {
                core::hint::spin_loop();
            }
            
            mmio_write(self.base, E1000E_TCTL, tctl & !TCTL_EN);
        }

        // Disable RX
        let rctl = mmio_read(self.base, E1000E_RCTL);
        mmio_write(self.base, E1000E_RCTL, rctl & !RCTL_EN);
        let _ = mmio_read(self.base, E1000E_RCTL); // flush
        let t_start = timer_now_as_micros();
        while timer_now_as_micros().wrapping_sub(t_start) < 150 {
            core::hint::spin_loop();
        }
    }

    // -----------------------------------------------------------------------
    // Full hardware reset + init
    // -----------------------------------------------------------------------
    unsafe fn reset_and_init(&mut self) -> DeviceResult {
        // 1. Pre-reset flush for I219
        self.flush_desc_rings();

        // 1b. Try reading MAC from hardware (BIOS initialized) before we reset it.
        self.read_mac_from_hw();
        let mut mac_found = self.is_valid_mac();
        if mac_found {
            info!(
                "[e1000e] found BIOS-initialized MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                self.mac[0], self.mac[1], self.mac[2], self.mac[3], self.mac[4], self.mac[5]
            );
        }

        // 2. Issue global reset (RST bit in CTRL).
        //    Before resetting, disable PCIe master and wait for it to take effect.
        let mut ctrl = mmio_read(self.base, E1000E_CTRL);
        mmio_write(self.base, E1000E_CTRL, ctrl | CTRL_GIO_MASTER_DISABLE);
        let t_master = timer_now_as_micros();
        while timer_now_as_micros().wrapping_sub(t_master) < 50_000 {
            if mmio_read(self.base, E1000E_STATUS) & STATUS_GIO_MASTER_ENABLE == 0 {
                break;
            }
            core::hint::spin_loop();
        }

        ctrl = mmio_read(self.base, E1000E_CTRL);
        mmio_write(self.base, E1000E_CTRL, ctrl | CTRL_RST);
        
        // Disable Wake-on-LAN
        mmio_write(self.base, E1000E_WUC, 0);
        mmio_write(self.base, E1000E_WUFC, 0);
        mmio_write(self.base, E1000E_WUS, 0);

        // Hard silence: spin for at least 10 ms, timed with the kernel clock.
        let t_rst = timer_now_as_micros();
        while timer_now_as_micros().wrapping_sub(t_rst) < POST_RST_US {
            if mmio_read(self.base, E1000E_CTRL) & CTRL_RST == 0 {
                break;
            }
            core::hint::spin_loop();
        }

        // 3. Poll STATUS until the device is ready (not 0xFFFF_FFFF = bus turnaround).
        //    Timeout after 150 ms — PCH-based NICs (I217/I218/I219) can need up
        //    to ~100 ms. Note: STATUS = 0 is a valid post-reset value (no link,
        //    speeds not yet resolved) and must NOT be treated as "not ready".
        let mut ready = false;
        let t_poll = timer_now_as_micros();
        while timer_now_as_micros().wrapping_sub(t_poll) < STATUS_POLL_US {
            let s = mmio_read(self.base, E1000E_STATUS);
            if s != 0xFFFF_FFFF {
                ready = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !ready {
            warn!("[e1000e] device did not respond after reset — aborting init");
            return Err(DeviceError::IoError);
        }

        // 4. Disable interrupts again (RST clears IMC)
        mmio_write(self.base, E1000E_IMC, 0xFFFF_FFFF);

        // 5. If we don't have a valid MAC yet, try reading from NVM.
        if !mac_found {
            info!("[e1000e] attempting NVM MAC read...");
            self.read_mac_from_nvm();
            mac_found = self.is_valid_mac();
            if mac_found {
                info!(
                    "[e1000e] MAC from NVM success: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    self.mac[0], self.mac[1], self.mac[2], self.mac[3], self.mac[4], self.mac[5]
                );
            }
        }

        // 5b. If still no MAC, try RAL0/RAH0 again (some NICs auto-load after reset).
        if !mac_found {
            info!("[e1000e] attempting post-reset RAL/RAH MAC read...");
            self.read_mac_from_hw();
            mac_found = self.is_valid_mac();
            if mac_found {
                info!(
                    "[e1000e] MAC from RAL0/RAH0 success: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    self.mac[0], self.mac[1], self.mac[2], self.mac[3], self.mac[4], self.mac[5]
                );
            }
        }

        if !mac_found {
            // Fallback to a distinct default MAC if all detection fails.
            self.mac = [0x00, 0x0E, 0x10, 0x00, 0x0E, 0x00];
            warn!(
                "[e1000e] all detection failed; using fallback: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                self.mac[0], self.mac[1], self.mac[2], self.mac[3], self.mac[4], self.mac[5]
            );
        }

        // 6. Set link-up + auto-speed detection. 
        // Also explicitly DISABLE flow control (TFCE | RFCE) and VLAN mode (VME).
        let ctrl = mmio_read(self.base, E1000E_CTRL);
        mmio_write(
            self.base,
            E1000E_CTRL,
            (ctrl | CTRL_SLU | CTRL_ASDE | CTRL_FD) & !(CTRL_TFCE | CTRL_RFCE | CTRL_VME | CTRL_GIO_MASTER_DISABLE),
        );

        // 7. Clear MTA (multicast table)
        for i in 0..E1000E_MTA_LEN {
            mmio_write(self.base, E1000E_MTA_BASE + i, 0);
        }

        // 8. Initialize hardware bits (e1000_initialize_hw_bits_ich8lan)
        let mut ctrl_ext = mmio_read(self.base, E1000E_CTRL_EXT);
        ctrl_ext |= 1 << 22; // Required bit
        if matches!(self.device_id, 0x1502..=0x1503 | 0x153a..=0x153b | 0x155a | 0x1559 | 0x15a0..=0x15a3 | 0x156f..=0x1570 | 0x15b7..=0x15be | 0x15d6..=0x15d8 | 0x15e3 | 0x0d4c..=0x0d4f | 0x15f4..=0x15fc | 0x1a1c..=0x1a1f | 0x0dc5..=0x0dc8 | 0x550a..=0x5511 | 0x57a0..=0x57a1 | 0x57b3..=0x57ba) {
            ctrl_ext |= CTRL_EXT_PHYPDEN;
        }
        ctrl_ext |= CTRL_EXT_RO_DIS;
        ctrl_ext &= !CTRL_EXT_DPG_EN; // Disable Dynamic Power Gating
        mmio_write(self.base, E1000E_CTRL_EXT, ctrl_ext);

        // Apply PCH-specific bits
        if matches!(self.device_id, 0x153a..=0x153b | 0x155a | 0x1559 | 0x15a0..=0x15a3 | 0x156f..=0x1570 | 0x15b7..=0x15be | 0x15d6..=0x15d8 | 0x15e3 | 0x0d4c..=0x0d4f | 0x15f4..=0x15fc | 0x1a1c..=0x1a1f | 0x0dc5..=0x0dc8 | 0x550a..=0x5511 | 0x57a0..=0x57a1 | 0x57b3..=0x57ba) {
            mmio_write(self.base, E1000E_CRC_OFFSET, 0x65656565);
            let kabgtxd = mmio_read(self.base, E1000E_KABGTXD);
            mmio_write(self.base, E1000E_KABGTXD, kabgtxd | KABGTXD_BGSQLBIAS);
        }

        // Set TXDCTL bits
        let mut txdctl = mmio_read(self.base, E1000E_TXDCTL);
        txdctl |= 1 << 22; // Required bit
        mmio_write(self.base, E1000E_TXDCTL, txdctl);

        // Set TARC bits
        let mut tarc0 = mmio_read(self.base, E1000E_TARC0);
        tarc0 |= (1 << 23) | (1 << 24) | (1 << 26) | (1 << 27);
        mmio_write(self.base, E1000E_TARC0, tarc0);

        let mut tarc1 = mmio_read(self.base, E1000E_TARC1);
        tarc1 |= (1 << 24) | (1 << 26) | (1 << 30);
        tarc1 |= 1 << 28; // Not MULR
        mmio_write(self.base, E1000E_TARC1, tarc1);

        // Enable ECC on Lynxpoint and later
        if matches!(self.device_id, 0x153a..=0x153b | 0x155a | 0x1559 | 0x15a0..=0x15a3 | 0x156f..=0x1570 | 0x15b7..=0x15be | 0x15d6..=0x15d8 | 0x15e3 | 0x0d4c..=0x0d4f | 0x15f4..=0x15fc | 0x1a1c..=0x1a1f | 0x0dc5..=0x0dc8 | 0x550a..=0x5511 | 0x57a0..=0x57a1 | 0x57b3..=0x57ba) {
            let pbeccsts = mmio_read(self.base, E1000E_PBECCSTS);
            mmio_write(self.base, E1000E_PBECCSTS, pbeccsts | PBECCSTS_ECC_ENABLE);
            
            let ctrl = mmio_read(self.base, E1000E_CTRL);
            mmio_write(self.base, E1000E_CTRL, ctrl | CTRL_MEHE);
        }

        // 6. Set receive address 0 (RAL0/RAH0) to our MAC
        let ral = (self.mac[0] as u32)
            | ((self.mac[1] as u32) << 8)
            | ((self.mac[2] as u32) << 16)
            | ((self.mac[3] as u32) << 24);
        let rah = (self.mac[4] as u32) | ((self.mac[5] as u32) << 8) | (1u32 << 31); // bit 31 = Address Valid
        unsafe {
            mmio_write(self.base, E1000E_RAL0, ral);
            mmio_write(self.base, E1000E_RAH0, rah);
        }

        // 9. Zero DMA rings and fill RX descriptor buffer pointers
        let rx_ring = self.rx_ring.as_ptr::<RxDesc>();
        let tx_ring = self.tx_ring.as_ptr::<TxDesc>();
        core::ptr::write_bytes(rx_ring, 0, NUM_RX);
        core::ptr::write_bytes(tx_ring, 0, NUM_TX);
        for i in 0..NUM_RX {
            let desc = unsafe { &mut *rx_ring.add(i) };
            desc.addr = self.rx_bufs[i].paddr() as u64;
            desc.length = 0;
            desc.status = 0;
        }
        
        // Ensure the zeroed rings and buffer addresses are flushed to memory
        // so that the NIC DMA engine sees the correct descriptors immediately.
        for i in 0..NUM_RX {
            unsafe { 
                core::arch::x86_64::_mm_clflush(self.rx_ring.as_ptr::<RxDesc>().add(i) as *const u8);
            };
        }
        for i in 0..NUM_TX {
            unsafe { core::arch::x86_64::_mm_clflush(self.tx_ring.as_ptr::<TxDesc>().add(i) as *const u8) };
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

        // 10. Configure TX ring
        let tx_ring_pa = self.tx_ring.paddr();
        mmio_write(self.base, E1000E_TDBAL, tx_ring_pa as u32);
        mmio_write(self.base, E1000E_TDBAH, (tx_ring_pa >> 32) as u32);
        mmio_write(
            self.base,
            E1000E_TDLEN,
            (NUM_TX * size_of::<TxDesc>()) as u32,
        );
        mmio_write(self.base, E1000E_TDH, 0);
        mmio_write(self.base, E1000E_TDT, 0);
        
        // TIPG: IPGT=8, IPGR1=8, IPGR2=12 (Linux default for ICH8+)
        mmio_write(self.base, E1000E_TIPG, 8u32 | (8 << 10) | (12 << 20));

        mmio_write(
            self.base,
            E1000E_TCTL,
            TCTL_EN | TCTL_PSP | TCTL_CT_16 | TCTL_COLD_64,
        );

        if matches!(self.device_id, 0x153a..=0x153b | 0x155a | 0x1559 | 0x15a0..=0x15a3 | 0x156f..=0x1570 | 0x15b7..=0x15be | 0x15d6..=0x15d8 | 0x15e3 | 0x0d4c..=0x0d4f | 0x15f4..=0x15fc | 0x1a1c..=0x1a1f | 0x0dc5..=0x0dc8 | 0x550a..=0x5511 | 0x57a0..=0x57a1 | 0x57b3..=0x57ba) {
            
            // Disable K1 in FEXTNVM6
            let mut fextnvm6 = mmio_read(self.base, E1000E_FEXTNVM6);
            fextnvm6 |= FEXTNVM6_K1_OFF_EN | FEXTNVM6_DIS_ELDW;
            mmio_write(self.base, E1000E_FEXTNVM6, fextnvm6);
            
            // Disable K1 in KMRNCTRLSTA
            let mut kmrn = self.kmrn_read(KMRNCTRLSTA_K1_CONFIG);
            kmrn &= !KMRNCTRLSTA_K1_ENABLE;
            self.kmrn_write(KMRNCTRLSTA_K1_CONFIG, kmrn);
            
            // Disable L1.2 power state in FEXTNVM11
            let mut fextnvm11 = mmio_read(self.base, E1000E_FEXTNVM11);
            fextnvm11 |= FEXTNVM11_DISABLE_L1_2;
            mmio_write(self.base, E1000E_FEXTNVM11, fextnvm11);

            // Set Beacon Duration in FEXTNVM4 to 8usec
            let mut fextnvm4 = mmio_read(self.base, E1000E_FEXTNVM4);
            fextnvm4 &= !FEXTNVM4_BEACON_DURATION_MASK;
            fextnvm4 |= FEXTNVM4_BEACON_DURATION_8USEC;
            mmio_write(self.base, E1000E_FEXTNVM4, fextnvm4);

            // Set FEXTNVM7 bits (bit 28 is NEED_DESCR_RING_FLUSH for I219)
            let mut fextnvm7 = mmio_read(self.base, E1000E_FEXTNVM7);
            fextnvm7 |= FEXTNVM7_SIDE_CLK_UNGATE | FEXTNVM7_DISABLE_SMB_PERST | FEXTNVM7_DIS_LR_PROMISC;
            mmio_write(self.base, E1000E_FEXTNVM7, fextnvm7);

            // Set FEXTNVM9 bits
            let mut fextnvm9 = mmio_read(self.base, E1000E_FEXTNVM9);
            fextnvm9 |= FEXTNVM9_IOSFSB_CLKGATE_DIS | FEXTNVM9_IOSFSB_CLKREQ_DIS;
            mmio_write(self.base, E1000E_FEXTNVM9, fextnvm9);

            // Set PBA (Packet Buffer Allocation)
            // Linux uses 18K for RX, 14K for TX on these chips to avoid drops.
            mmio_write(self.base, E1000E_PBA, 0x000E0012);
        } else {
            // Default PBA for older e1000e
            mmio_write(self.base, E1000E_PBA, 0x00100030);
        }

        // 11. Configure RX ring
        let rx_ring_pa = self.rx_ring.paddr();
        mmio_write(self.base, E1000E_RDBAL, rx_ring_pa as u32);
        mmio_write(self.base, E1000E_RDBAH, (rx_ring_pa >> 32) as u32);
        mmio_write(
            self.base,
            E1000E_RDLEN,
            (NUM_RX * size_of::<RxDesc>()) as u32,
        );
        unsafe { mmio_write(self.base, E1000E_RDH, 0) };
        unsafe { mmio_write(self.base, E1000E_RDT, 0) }; // Will be set to NUM_RX-1 after RCTL_EN
        self.rx_tail = 0; // rx_tail tracks the next descriptor to check

        // 6c. Disable RX Delay Timers for immediate write-back
        unsafe { mmio_write(self.base, E1000E_RDTR, 0) };
        unsafe { mmio_write(self.base, E1000E_RADV, 0) };
        unsafe { mmio_write(self.base, E1000E_ITR, 0) }; // Also disable Interrupt Throttling
        
        // 6b. Zero Multicast Table Array (MTA)
        for i in 0..128 {
            unsafe { mmio_write(self.base, E1000E_MTA_BASE + i, 0) };
        }
        
        unsafe {
            mmio_write(self.base, E1000E_RXCSUM, 0); // Disable RX checksum offload
            // Disable NFS filtering and IPv6 extension header parsing which can hang RX
            let rfctl = RFCTL_NFSW_DIS | RFCTL_NFSR_DIS | RFCTL_IPV6_EX_DIS | RFCTL_NEW_IPV6_EXT_DIS;
            mmio_write(self.base, E1000E_RFCTL, rfctl);
            mmio_write(self.base, E1000E_MRQC, 0);   // Disable RSS / multiple queues
            mmio_write(self.base, E1000E_VET, 0);    // Clear VLAN EtherType
            
            // SPT/KBL Si errata workaround to avoid data corruption (IOSFPC bit 16)
            if matches!(self.device_id, 0x156f..=0x1570 | 0x15b7..=0x15be) {
                let iosfpc = mmio_read(self.base, E1000E_IOSFPC);
                mmio_write(self.base, E1000E_IOSFPC, iosfpc | 0x00010000);
            }
        }

        // Set RXDCTL - write-back thresholds.
        // On I219, we want immediate write-back (WTHRESH=1) or even better, 
        // set some thresholds to avoid drops.
        unsafe {
            mmio_write(self.base, E1000E_RXDCTL, (1 << 16) | (1 << 24)); // WTHRESH=1, GRAN=1
        };

        // Initialize SRRCTL for Legacy descriptors and 2KB buffer size
        // BSIZEPACKET = 2 (units of 1KB = 2048 bytes)
        // DESCTYPE = 000 (Legacy)
        unsafe {
            mmio_write(self.base, E1000E_SRRCTL, 2);
        }

        // 7. Enable receiver
        // EN: bit 1, SBP: bit 2, UPE: bit 3 (unicast promisc, accept directed frames),
        // MPE: bit 4, BAM: bit 15, SECRC: bit 26
        let rctl = RCTL_EN | RCTL_SBP | RCTL_UPE | RCTL_MPE | RCTL_BAM | RCTL_SECRC | RCTL_BSIZE_2K;
        unsafe { mmio_write(self.base, E1000E_RCTL, rctl) };
        
        // Set TXDCTL (TX Descriptor Control)
        // GRAN=1, FULL_TX_DESC_WB=1, PTHRESH=31
        unsafe { mmio_write(self.base, E1000E_TXDCTL, TXDCTL_GRAN | TXDCTL_FULL_TX_DESC_WB | 0x1F) };

        // Flow control watermarks (Linux defaults)
        unsafe {
            mmio_write(self.base, E1000E_FCTTV, 0xFFFF);
            mmio_write(self.base, E1000E_FCRTV, 0xFFFF);
            mmio_write(self.base, E1000E_FCRTL, 0x05048);
            mmio_write(self.base, E1000E_FCRTH, 0x05C20);
        }

        // Wait a bit for the receiver to stabilize
        for _ in 0..1000 { unsafe { core::arch::x86_64::_mm_pause() }; }

        // CRITICAL: Set RDT *AFTER* RCTL_EN per datasheet §13.4.18
        unsafe { mmio_write(self.base, E1000E_RDT, (NUM_RX - 1) as u32) };

        // 12. Clear any pending interrupts, then enable all interrupts
        let _ = mmio_read(self.base, E1000E_ICR);
        mmio_write(self.base, E1000E_IMS, 0xFFFF_FFFF);
        
        // Disable interrupt throttling and delay timers for lower latency/polling
        mmio_write(self.base, E1000E_ITR, 0);
        mmio_write(self.base, E1000E_RDTR, 0);
        mmio_write(self.base, E1000E_RADV, 0);

        let status = mmio_read(self.base, E1000E_STATUS);
        
        info!(
            "[e1000e] init done. STATUS={:#010x} link={}",
            status,
            if status & STATUS_LU != 0 {
                "UP"
            } else {
                "DOWN"
            }
        );
        Ok(())
    }

    fn receive(&mut self) -> Option<Vec<u8>> {
        loop {
            let ring = self.rx_ring.as_ptr::<RxDesc>();
            let idx = self.rx_tail;
            let desc = unsafe { &mut *ring.add(idx) };

            // Ensure we see the latest descriptor content from memory.
            // On x86_64, PCIe DMA is usually coherent, but I219-V has quirks
            // and clflush ensures the CPU cache doesn't have stale data.
            unsafe {
                core::arch::x86_64::_mm_clflush(desc as *const RxDesc as *const u8);
            }
            core::sync::atomic::fence(Ordering::SeqCst);

            // Check DD bit in Legacy format (offset 12, bit 0).
            let status = unsafe { read_volatile(&desc.status) };
            if (status & 0x01) == 0 {
                return None;
            }

            // Packet is ready!
            let len = unsafe { read_volatile(&desc.length) };
            warn!("[e1000e] RX packet: {} bytes (idx={})", len, idx);

            if len == 0 || len as usize > BUF_SIZE {
                warn!("[e1000e] RX invalid length: {} (idx={})", len, idx);
                self.recycle_rx_desc(idx, desc);
                continue;
            }

            core::sync::atomic::fence(Ordering::SeqCst);

            let buf_vaddr = self.rx_bufs[idx].vaddr();
            
            // Flush the data buffer before reading it to ensure we see hardware's data
            for p in (buf_vaddr..buf_vaddr + len as usize).step_by(64) {
                unsafe { core::arch::x86_64::_mm_clflush(p as *const u8); }
            }
            core::sync::atomic::fence(Ordering::SeqCst);

            let buf = unsafe { core::slice::from_raw_parts(buf_vaddr as *const u8, len as usize) };
            let pkt = buf.to_vec();

            // Track stats
            self.stats.rx_packets += 1;
            self.stats.rx_bytes += len as u64;

            self.recycle_rx_desc(idx, desc);
            return Some(pkt);
        }
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
    fn send(&mut self, data: &[u8]) -> DeviceResult {
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
        /*
        warn!("[e1000e] TX check: idx={}, TDH={}, TDT={}, STATUS={:#x}, desc0_status={:#x}", 
            idx, tdh, tdt, status, unsafe { (*self.tx_ring.as_ptr::<TxDesc>()).status });
        */

        if self.tx_tail == 0 {
            self.tx_first = false;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Handle interrupt — returns true if there was something pending
    // -----------------------------------------------------------------------
    pub fn handle_interrupt(&mut self) -> bool {
        let icr = unsafe { mmio_read(self.base, E1000E_ICR) };
        // ICR is Read-to-Clear. No need to write back unless using MSI-X or specific modes.
        if icr != 0 {
            // warn!("[e1000e] ICR={:#x}", icr);
            true
        } else {
            false
        }
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

        // Fast check of ICR without holding the main hardware lock.
        // Reading ICR is Read-to-Clear, effectively acknowledging the interrupt at the source.
        // This prevents IRQ storms on single-core systems while we wait for the lock.
        let icr = unsafe { mmio_read(self.base, E1000E_ICR) };
        if icr == 0 {
            return;
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
        // warn!("[e1000e] poll() called");
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
        // Receive a pending packet without holding the hw lock during the copy.
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
        // Acquire the lock once for both the can_send check and the actual send.
        // Do NOT split into two lock() calls: the temporary guard from the first
        // lock() in an `if` condition lives through the entire if-body, which
        // would cause the second lock() to spin forever (deadlock).
        let mut hw = self.driver.hw.lock();
        if hw.can_send() {
            hw.send(data)?;
            Ok(data.len())
        } else {
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
    device_id: u16,
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
        device_id,
        mac: [0u8; 6], // Read from hardware during reset
        rx_ring,
        rx_bufs,
        rx_tail: 0,
        tx_ring,
        tx_bufs,
        tx_tail: 0,
        tx_head_shadow: 0,
        tx_first: true,
        stats: NetStats::default(),
    };

    unsafe {
        let ral = mmio_read(vaddr, E1000E_RAL0);
        let rah = mmio_read(vaddr, E1000E_RAH0);
        hw.mac[0..4].copy_from_slice(&ral.to_le_bytes());
        hw.mac[4..6].copy_from_slice(&rah.to_le_bytes()[..2]);
        hw.reset_and_init()?;
    }

    let mac_bytes = hw.mac;
    info!(
        "[e1000e] finalized MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (ID: {:#x})",
        mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5], device_id
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
        let vector = irq.map(|idx| idx + 32).unwrap_or(0);
        let iface = init(name, dev.id.device_id, vector, vaddr, 0)?;
        let iface_arc = Arc::new(iface);
        if vector != 0 {
            crate::net::pci_note_pending_msi(vector, iface_arc.clone());
        }
        Ok(Device::Net(iface_arc))
    }
}
