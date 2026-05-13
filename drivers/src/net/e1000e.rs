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

use super::timer_now_as_micros;

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

// CTRL bits
const CTRL_RST: u32 = 1 << 26; // full MAC + PHY reset
const CTRL_SLU: u32 = 1 << 6; // set link up
const CTRL_ASDE: u32 = 1 << 5; // auto-speed detection enable

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

        // 6. Set link-up + auto-speed detection
        let ctrl = mmio_read(self.base, E1000E_CTRL);
        const CTRL_ILOS: u32 = 1 << 7;
        mmio_write(self.base, E1000E_CTRL, ctrl | CTRL_SLU | CTRL_ASDE);

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
            unsafe { mmio_write(self.base, 0x05200 + (i * 4), 0) };
        }
        
        // Set PBA (Packet Buffer Allocation)
        // 0x100030: 16KB for RX, 48KB for TX
        unsafe { mmio_write(self.base, 0x01000, 0x00100030) };

        // 7. Enable receiver
        // 6. Enable RX
        // EN: bit 1, SBP: bit 2, UPE: bit 3, MPE: bit 4, LPE: bit 5, BAM: bit 15, SECRC: bit 26
        let rctl = RCTL_EN | RCTL_SBP | RCTL_UPE | RCTL_MPE | RCTL_LPE | RCTL_BAM | RCTL_SECRC | RCTL_BSIZE_2K;
        warn!("[e1000e] setting RCTL={:#x}", rctl);
        unsafe { mmio_write(self.base, E1000E_RCTL, rctl) };
        
        // Set RXDCTL (RX Descriptor Control)
        // GRAN=1 (descriptors), WTHRESH=0 (write back immediately)
        unsafe { mmio_write(self.base, 0x02828, (1 << 24)) };
        
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
        
        warn!(
            "[e1000e] INIT DUMP: STATUS={:#x}, RCTL={:#x}, TCTL={:#x}",
            status, rctl, tctl
        );
        warn!(
            "[e1000e] RX DUMP: RDBA={:#x}:{:x}, RDLEN={}, RDH={}, RDT={}",
            rdbah, rdbal, rdlen, rdh, rdt
        );
        warn!(
            "[e1000e] RX RING PADDR: {:#x}, BUF0 PADDR: {:#x}",
            self.rx_ring.paddr(), self.rx_bufs[0].paddr()
        );
        
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
        unsafe { core::arch::x86_64::_mm_clflush(desc as *const _ as *const u8); }
        core::sync::atomic::compiler_fence(Ordering::SeqCst);

        let rdh = unsafe { mmio_read(self.base, E1000E_RDH) };
        let rdt = unsafe { mmio_read(self.base, E1000E_RDT) };
        // trace!("[e1000e] RX check: idx={}, RDH={}, RDT={}, status={:#x}", idx, rdh, rdt, desc.status);

        if desc.status & RX_STATUS_DD == 0 {
            return None;
        }
        // Must be a complete frame and fit in our DMA buffer.
        if desc.status & RX_STATUS_EOP == 0 || (desc.len as usize) > BUF_SIZE {
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
        self.tx_first || (desc.status & 0x01 != 0) // DD bit
    }

    // -----------------------------------------------------------------------
    // Send one frame
    // -----------------------------------------------------------------------
    fn send(&mut self, data: &[u8]) -> DeviceResult {
        warn!("[e1000e] hardware sending {} bytes: {:02x?}", data.len(), &data[..data.len().min(32)]);
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
}

impl Scheme for E1000eInterface {
    fn name(&self) -> &str {
        "e1000e"
    }

    fn handle_irq(&self, irq: usize) {
        if irq != self.irq {
            return;
        }
        // Use try_lock to avoid deadlock in IRQ context
        if let Some(mut hw) = self.driver.hw.try_lock() {
            if hw.handle_interrupt() {
                let self_clone = self.clone();
                crate::utils::deferred_job::push_deferred_job(move || {
                    let ts = Instant::from_micros(timer_now_as_micros() as i64);
                    let sockets = get_sockets();
                    let mut sockets = sockets.lock();
                    if let Err(e) = self_clone.iface.lock().poll(&mut sockets, ts) {
                        // poll error is common when no packet, ignore
                    }
                });
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
        let mut sockets = sockets.lock();
        let _ = self.iface.lock().poll(&mut sockets, ts);
        Ok(())
    }
    fn recv(&self, buf: &mut [u8]) -> DeviceResult<usize> {
        // Try to read directly from hardware.
        if let Some(pkt) = self.driver.hw.lock().receive() {
            let n = pkt.len().min(buf.len());
            buf[..n].copy_from_slice(&pkt[..n]);
            Ok(n)
        } else {
            Err(DeviceError::NotReady)
        }
    }
    fn send(&self, data: &[u8]) -> DeviceResult<usize> {
        if self.driver.hw.lock().can_send() {
            let mut hw = self.driver.hw.lock();
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
        let iface = init(name, vector, vaddr, 0)?;
        Ok(Device::Net(Arc::new(iface)))
    }
}
