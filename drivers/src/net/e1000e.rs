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
use crate::scheme::{NetScheme, Scheme, SchemeUpcast};
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
const E1000E_FEXTNVM6: usize = 0x0010 / 4;
const E1000E_FEXTNVM7: usize = 0x0014 / 4;
const E1000E_FEXTNVM11: usize = 0x05BBC / 4;
const E1000E_KMRNCTRLSTA: usize = 0x00034 / 4;
const E1000E_PBA: usize = 0x01000 / 4;

// FEXTNVM6 bits
const FEXTNVM6_K1_OFF_EN: u32 = 1 << 31;
const FEXTNVM6_DIS_ELDW: u32 = 1 << 5; // Disable Early Link Down Window

// FEXTNVM7 bits
const FEXTNVM7_DIS_LR_PROMISC: u32 = 1 << 28;

// FEXTNVM11 bits
const FEXTNVM11_DISABLE_L1_2: u32 = 0x00000001;

// KMRNCTRLSTA bits
const KMRNCTRLSTA_K1_CONFIG: u32 = 1 << 13;

// CTRL bits
const CTRL_SLU: u32 = 1 << 6; // set link up
const CTRL_ASDE: u32 = 1 << 5; // auto-speed detection enable
const CTRL_RST: u32 = 1 << 26; // full MAC + PHY reset
const CTRL_TFCE: u32 = 1 << 27; // Transmit Flow Control Enable
const CTRL_RFCE: u32 = 1 << 28; // Receive Flow Control Enable
const CTRL_VME: u32 = 1 << 30; // VLAN Mode Enable

// STATUS bits
const STATUS_LU: u32 = 1 << 1; // link up

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
#[derive(Copy, Clone, Default)]
struct RxDesc {
    addr: u64,
    len: u16,
    chksum: u16,
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
}

impl E1000eHw {
    fn recycle_rx_desc(&mut self, idx: usize, desc: &mut RxDesc) {
        desc.status = 0;
        desc.errors = 0;
        fence(Ordering::SeqCst);
        self.rx_tail = (idx + 1) % NUM_RX;
        // CRITICAL: Hardware only sees the new descriptors when we update RDT.
        unsafe { mmio_write(self.base, E1000E_RDT, idx as u32) };
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
        info!("[e1000e] hardware registers: RAL0={:#010x}, RAH0={:#010x}", ral, rah);
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
    // Full hardware reset + init
    // -----------------------------------------------------------------------
    unsafe fn reset_and_init(&mut self) -> DeviceResult {
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
        //    CRITICAL: On e1000e (I217/I218/I219/82574) the datasheet (§4.6)
        //    requires NO MMIO reads for at least 10 ms after setting RST.
        //    Reading MMIO during that window can stall the PCI bus on real HW.
        //    Use a real timer so the delay is correct on fast CPUs.
        let ctrl = mmio_read(self.base, E1000E_CTRL);
        mmio_write(self.base, E1000E_CTRL, ctrl | CTRL_RST);

        // Hard silence: spin for at least 10 ms, timed with the kernel clock.
        let t_rst = timer_now_as_micros();
        while timer_now_as_micros().wrapping_sub(t_rst) < POST_RST_US {
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
        // Also explicitly DISABLE flow control (TFCE/RFCE) and VLAN mode (VME).
        let ctrl = mmio_read(self.base, E1000E_CTRL);
        mmio_write(
            self.base,
            E1000E_CTRL,
            (ctrl | CTRL_SLU | CTRL_ASDE) & !(CTRL_TFCE | CTRL_RFCE | CTRL_VME),
        );

        // 7. Clear MTA (multicast table)
        for i in 0..E1000E_MTA_LEN {
            mmio_write(self.base, E1000E_MTA_BASE + i, 0);
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
            (*rx_ring.add(i)).addr = self.rx_bufs[i].paddr() as u64;
        }

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
        mmio_write(
            self.base,
            E1000E_TCTL,
            TCTL_EN | TCTL_PSP | TCTL_CT_16 | TCTL_COLD_64,
        );
        // TIPG: IPGT=10, IPGR1=8, IPGR2=12 (IEEE 802.3 recommended)
        mmio_write(self.base, E1000E_TIPG, 10u32 | (8 << 10) | (12 << 20));

        // 10b. Apply Linux-style workarounds for PCH-based NICs (I217/I218/I219)
        // These are critical for fixing broadcast packet drops (DHCP).
        if matches!(self.device_id, 0x153a | 0x153b | 0x155a | 0x1559 | 0x15a0 | 0x15a1 | 0x15a2 | 0x15a3 | 0x15b7 | 0x15b8 | 0x15b9 | 0x15bc | 0x15bd | 0x15be | 0x15bb | 0x0d4c | 0x0d4d | 0x0d4e | 0x0d4f | 0x1a1c | 0x1a1d | 0x1a1e | 0x1a1f) {
            warn!("[e1000e] applying I217/I218/I219 broadcast workarounds (K1, ELDW, L1.2)");
            
            // Disable K1 in FEXTNVM6
            let mut fextnvm6 = mmio_read(self.base, E1000E_FEXTNVM6);
            fextnvm6 |= FEXTNVM6_K1_OFF_EN | FEXTNVM6_DIS_ELDW;
            mmio_write(self.base, E1000E_FEXTNVM6, fextnvm6);
            
            // Disable K1 in KMRNCTRLSTA
            let mut kmrn = mmio_read(self.base, E1000E_KMRNCTRLSTA);
            kmrn &= !KMRNCTRLSTA_K1_CONFIG;
            mmio_write(self.base, E1000E_KMRNCTRLSTA, kmrn);
            
            // Disable L1.2 power state in FEXTNVM11
            let mut fextnvm11 = mmio_read(self.base, E1000E_FEXTNVM11);
            fextnvm11 |= FEXTNVM11_DISABLE_L1_2;
            mmio_write(self.base, E1000E_FEXTNVM11, fextnvm11);

            // Set PBA (Packet Buffer Allocation)
            // Linux uses 18K for RX, 14K for TX on these chips to avoid drops.
            // 0x000E0012: RX=18, TX=14 (or similar depending on chip)
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
        unsafe { mmio_write(self.base, E1000E_RDT, 0) };
        self.rx_tail = 0; // rx_tail now tracks the next descriptor to check

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
            mmio_write(self.base, E1000E_RFCTL, 0);  // Disable advanced filtering
            mmio_write(self.base, E1000E_MRQC, 0);   // Disable RSS / multiple queues
            mmio_write(self.base, E1000E_VET, 0);    // Clear VLAN EtherType
        }

        // 7. Enable receiver
        // EN: bit 1, SBP: bit 2, MPE: bit 4, BAM: bit 15, SECRC: bit 26
        let rctl = RCTL_EN | RCTL_SBP | RCTL_MPE | RCTL_BAM | RCTL_SECRC | RCTL_BSIZE_2K;
        unsafe { mmio_write(self.base, E1000E_RCTL, rctl) };
        
        // Set RXDCTL (RX Descriptor Control)
        // GRAN=1 (descriptors), WTHRESH=0 (write back immediately)
        unsafe { mmio_write(self.base, 0x02828 / 4, (1 << 24)) };
        
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
        let rctl = mmio_read(self.base, E1000E_RCTL);
        let tctl = mmio_read(self.base, E1000E_TCTL);
        let rdbal = mmio_read(self.base, E1000E_RDBAL);
        let rdbah = mmio_read(self.base, E1000E_RDBAH);
        let rdlen = mmio_read(self.base, E1000E_RDLEN);
        let rdh = mmio_read(self.base, E1000E_RDH);
        let rdt = mmio_read(self.base, E1000E_RDT);
        
        
        
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

    // -----------------------------------------------------------------------
    // Receive one frame (returns owned Vec)
    // -----------------------------------------------------------------------
    fn receive(&mut self) -> Option<Vec<u8>> {
        let ring = self.rx_ring.as_ptr::<RxDesc>();
        let idx = self.rx_tail;
        let desc = unsafe { &mut *ring.add(idx) };

        fence(Ordering::SeqCst);
        let status = unsafe { read_volatile(&desc.status) };
        core::sync::atomic::compiler_fence(Ordering::SeqCst);

        let rdh = unsafe { mmio_read(self.base, E1000E_RDH) };
        let rdt = unsafe { mmio_read(self.base, E1000E_RDT) };
        // trace!("[e1000e] RX check: idx={}, RDH={}, RDT={}, status={:#x}", idx, rdh, rdt, desc.status);

        if status & RX_STATUS_DD == 0 {
            return None;
        }
        let errors = unsafe { read_volatile(&desc.errors) };
        // Check for hardware reported errors
        if errors != 0 {
            warn!("[e1000e] RX packet error: status={:#x}, errors={:#x}, len={}", status, errors, desc.len);
        }

        // Must be a complete frame and fit in our DMA buffer.
        if status & RX_STATUS_EOP == 0 || (desc.len as usize) > BUF_SIZE {
            self.recycle_rx_desc(idx, desc);
            return None;
        }
        let len = desc.len as usize;
        // Flush the buffer before reading it
        let buf_vaddr = self.rx_bufs[idx].vaddr();
        for p in (buf_vaddr..buf_vaddr + len).step_by(64) {
            unsafe { core::arch::x86_64::_mm_clflush(p as *const u8); }
        }
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        let buf = unsafe { core::slice::from_raw_parts(buf_vaddr as *const u8, len) };
        let pkt = buf.to_vec();

        self.recycle_rx_desc(idx, desc);
        Some(pkt)
    }

    // -----------------------------------------------------------------------
    // Check if a TX slot is available
    // -----------------------------------------------------------------------
    fn can_send(&self) -> bool {
        let ring = self.tx_ring.as_ptr::<TxDesc>();
        let desc = unsafe { &*ring.add(self.tx_tail) };
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

        desc.addr = self.tx_bufs[idx].paddr() as u64;
        desc.len = data.len() as u16;
        desc.cmd = TX_CMD_EOP | TX_CMD_IFCS | TX_CMD_RS;
        desc.status = 0;
        fence(Ordering::SeqCst);

        self.tx_tail = (idx + 1) % NUM_TX;
        unsafe { mmio_write(self.base, E1000E_TDT, self.tx_tail as u32) };
        fence(Ordering::SeqCst);

        let tdh = unsafe { mmio_read(self.base, E1000E_TDH) };
        let tdt = unsafe { mmio_read(self.base, E1000E_TDT) };
        let status = unsafe { mmio_read(self.base, E1000E_STATUS) };
        warn!("[e1000e] TX check: idx={}, TDH={}, TDT={}, STATUS={:#x}, desc0_status={:#x}", 
            idx, tdh, tdt, status, unsafe { (*self.tx_ring.as_ptr::<TxDesc>()).status });

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
        if icr != 0 {
            warn!("[e1000e] ICR={:#x}", icr);
            unsafe { mmio_write(self.base, E1000E_ICR, icr) };
            return true;
        }
        false
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
    pub poll_pending: Arc<core::sync::atomic::AtomicBool>,
}

impl Scheme for E1000eInterface {
    fn name(&self) -> &str {
        "e1000e"
    }

    fn handle_irq(&self, irq: usize) {
        if irq != self.irq {
            return;
        }
        // Use try_lock to avoid deadlock if the main thread is currently polling.
        // On real hardware (especially single-core), if we spin here, we deadlock.
        if let Some(mut hw) = self.driver.hw.try_lock() {
            if hw.handle_interrupt() {
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
        let flag = intr_get();
        if flag { intr_off(); }
        let res = if let Some(pkt) = self.driver.hw.lock().receive() {
            let n = pkt.len().min(buf.len());
            buf[..n].copy_from_slice(&pkt[..n]);
            Ok(n)
        } else {
            Err(DeviceError::NotReady)
        };
        if flag { intr_on(); }
        res
    }
    fn send(&self, data: &[u8]) -> DeviceResult<usize> {
        let flag = intr_get();
        if flag { intr_off(); }
        let res = if self.driver.hw.lock().can_send() {
            let mut hw = self.driver.hw.lock();
            hw.send(data)?;
            Ok(data.len())
        } else {
            Err(DeviceError::NotReady)
        };
        if flag { intr_on(); }
        res
    }

    fn can_recv(&self) -> bool {
        // Return true so callers always attempt recv(); actual receive will return NotReady if nothing.
        true
    }

    fn can_send(&self) -> bool {
        self.driver.hw.lock().can_send()
    }

    fn add_route(&self, _cidr: IpCidr, gateway: Option<smoltcp::wire::IpAddress>) -> DeviceResult {
        info!("[e1000e] adding default route via {:?}", gateway);
        let mut iface = self.iface.lock();
        if let Some(IpAddress::Ipv4(gw)) = gateway {
            iface
                .routes_mut()
                .add_default_ipv4_route(gw)
                .map_err(|_| DeviceError::IoError)?;
        }
        info!("[e1000e] default route added");
        Ok(())
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
        caps.max_transmission_unit = 1514;
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
        super::net_dispatch_packet(&buf);
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
        mac: [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01],
        rx_ring,
        rx_bufs,
        rx_tail: 0,
        tx_ring,
        tx_bufs,
        tx_tail: 0,
        tx_head_shadow: 0,
        tx_first: true,
    };

    unsafe {
        hw.reset_and_init()?;
    }

    let mac_bytes = hw.mac;
    info!(
        "[e1000e] finalized MAC for smoltcp: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5]
    );
    let hw_arc = Arc::new(Mutex::new(hw));
    let driver = E1000eDriver { hw: hw_arc.clone() };

    let ethernet_addr = EthernetAddress::from_bytes(&mac_bytes);
    let ip_addrs = [IpCidr::new(IpAddress::v4(10, 0, 2, 15), 24)];
    let default_v4_gw = Ipv4Address::new(10, 0, 2, 2);
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
        poll_pending: Arc::new(core::sync::atomic::AtomicBool::new(false)),
    };

    Ok(e1000e_iface)
}

pub struct E1000eDriverPci;

impl PciDriver for E1000eDriverPci {
    fn name(&self) -> &str {
        "e1000e"
    }

    fn matched(&self, vendor_id: u16, device_id: u16) -> bool {
        vendor_id == 0x8086 && matches!(device_id,
            0x10bf | 0x10cb | 0x10cc | 0x10cd | 0x10ce |
            0x10de | 0x10df | 0x10e5 | 0x10f5 |
            0x10ea | 0x10eb | 0x10ef | 0x10f0 |
            0x1502 | 0x1503 |
            0x153a | 0x153b |
            0x155a | 0x1559 | 0x15a0 | 0x15a1 | 0x15a2 | 0x15a3 |
            0x10d3 |
            0x15b7 | 0x15b8 | 0x15b9 |
            0x15bc | 0x15bd | 0x15be |
            0x15d6 | 0x15d7 | 0x15d8 |
            0x15e3 | 0x15d9 | 0x15bb | 0x15da |
            0x15df | 0x15e0 | 0x15e1 | 0x15e2 |
            0x15f4 | 0x15f5 | 0x15f9 | 0x15fa | 0x15fb | 0x15fc |
            0x0d4c | 0x0d4d | 0x0d4e | 0x0d4f |
            0x1a1c | 0x1a1d | 0x1a1e | 0x1a1f |
            0x550a | 0x550b | 0x550c | 0x550d | 0x550e | 0x550f |
            0x5502 | 0x5503 |
            0x57a0 | 0x57a1 | 0x57b3
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
