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
use crate::scheme::{NetScheme, Scheme};
use crate::{DeviceError, DeviceResult};
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

// EERD bits (e1000e uses bit 4 for DONE, NOT bit 1 like the legacy e1000)
const EERD_START: u32 = 1 << 0;
const EERD_DONE: u32 = 1 << 4; // bit 4 on e1000e / 82574L
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
const RCTL_BAM: u32 = 1 << 15; // broadcast accept
const RCTL_BSIZE_4K: u32 = (3 << 16) | (1 << 25); // BSIZE=3, BSEX=1 → 4096 B
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
const BUF_SIZE: usize = 4096;

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
struct E1000eHw {
    base: usize, // MMIO virtual base
    mac: [u8; 6],

    rx_ring_va: usize,
    rx_ring_pa: usize,
    rx_bufs_va: Vec<usize>,
    rx_bufs_pa: Vec<usize>,
    rx_tail: usize,

    tx_ring_va: usize,
    tx_ring_pa: usize,
    tx_bufs_va: Vec<usize>,
    tx_bufs_pa: Vec<usize>,
    tx_tail: usize,
    tx_head_shadow: usize,
    tx_first: bool,
}

impl E1000eHw {
    fn recycle_rx_desc(&mut self, idx: usize, desc: &mut RxDesc) {
        desc.status = 0;
        desc.errors = 0;
        desc.addr = self.rx_bufs_pa[idx] as u64;
        fence(Ordering::SeqCst);
        self.rx_tail = idx;
        unsafe { mmio_write(self.base, E1000E_RDT, idx as u32) };
    }

    // -----------------------------------------------------------------------
    // NVM word read via EERD (works on all e1000e silicon)
    // -----------------------------------------------------------------------
    unsafe fn nvm_read_word(&self, offset: u16) -> u16 {
        let cmd = ((offset as u32) << EERD_ADDR_SHIFT) | EERD_START;
        mmio_write(self.base, E1000E_EERD, cmd);
        // Poll DONE bit with a real timer so the timeout is correct on any CPU.
        let t0 = timer_now_as_micros();
        loop {
            let v = mmio_read(self.base, E1000E_EERD);
            if v & EERD_DONE != 0 {
                return (v >> EERD_DATA_SHIFT) as u16;
            }
            if timer_now_as_micros().wrapping_sub(t0) >= NVM_POLL_US {
                warn!("[e1000e] NVM read timeout at offset {}", offset);
                return 0;
            }
            core::hint::spin_loop();
        }
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
        // 1. Disable all interrupts before reset
        mmio_write(self.base, E1000E_IMC, 0xFFFF_FFFF);
        // Flush with a read (device still alive here)
        let _ = mmio_read(self.base, E1000E_STATUS);

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

        // 5. Read MAC from NVM
        self.read_mac_from_nvm();

        // 6. Set link-up + auto-speed detection
        let ctrl = mmio_read(self.base, E1000E_CTRL);
        mmio_write(self.base, E1000E_CTRL, ctrl | CTRL_SLU | CTRL_ASDE);

        // 7. Clear MTA (multicast table)
        for i in 0..E1000E_MTA_LEN {
            mmio_write(self.base, E1000E_MTA_BASE + i, 0);
        }

        // 8. Program receive address (RAL/RAH)
        let ral = (self.mac[0] as u32)
            | ((self.mac[1] as u32) << 8)
            | ((self.mac[2] as u32) << 16)
            | ((self.mac[3] as u32) << 24);
        let rah = (self.mac[4] as u32) | ((self.mac[5] as u32) << 8) | (1u32 << 31); // AV (Address Valid) bit
        mmio_write(self.base, E1000E_RAL0, ral);
        mmio_write(self.base, E1000E_RAH0, rah);

        // 9. Zero DMA rings and fill RX descriptor buffer pointers
        let rx_ring = self.rx_ring_va as *mut RxDesc;
        let tx_ring = self.tx_ring_va as *mut TxDesc;
        core::ptr::write_bytes(rx_ring, 0, NUM_RX);
        core::ptr::write_bytes(tx_ring, 0, NUM_TX);
        for i in 0..NUM_RX {
            (*rx_ring.add(i)).addr = self.rx_bufs_pa[i] as u64;
        }

        // 10. Configure TX ring
        mmio_write(self.base, E1000E_TDBAL, self.tx_ring_pa as u32);
        mmio_write(self.base, E1000E_TDBAH, (self.tx_ring_pa >> 32) as u32);
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
        mmio_write(self.base, E1000E_RDBAL, self.rx_ring_pa as u32);
        mmio_write(self.base, E1000E_RDBAH, (self.rx_ring_pa >> 32) as u32);
        mmio_write(
            self.base,
            E1000E_RDLEN,
            (NUM_RX * size_of::<RxDesc>()) as u32,
        );
        mmio_write(self.base, E1000E_RDH, 0);
        mmio_write(self.base, E1000E_RDT, (NUM_RX - 1) as u32);
        mmio_write(
            self.base,
            E1000E_RCTL,
            RCTL_EN | RCTL_BAM | RCTL_BSIZE_4K | RCTL_SECRC,
        );

        // 12. Clear any pending interrupts, then enable RX (RXT0 = bit 7)
        mmio_write(self.base, E1000E_ICR, 0xFFFF_FFFF);
        mmio_write(self.base, E1000E_IMS, 1 << 7);

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

    // -----------------------------------------------------------------------
    // Receive one frame (returns owned Vec)
    // -----------------------------------------------------------------------
    fn receive(&mut self) -> Option<Vec<u8>> {
        let ring = self.rx_ring_va as *mut RxDesc;
        let next = (self.rx_tail + 1) % NUM_RX;
        let desc = unsafe { &mut *ring.add(next) };

        fence(Ordering::SeqCst);
        // Status bit 0 = DD (Descriptor Done)
        if desc.status & RX_STATUS_DD == 0 {
            return None;
        }
        // Must be a complete frame and fit in our DMA buffer.
        if desc.status & RX_STATUS_EOP == 0 || (desc.len as usize) > BUF_SIZE {
            self.recycle_rx_desc(next, desc);
            return None;
        }
        let len = desc.len as usize;
        let buf = unsafe { core::slice::from_raw_parts(self.rx_bufs_va[next] as *const u8, len) };
        let pkt = buf.to_vec();

        self.recycle_rx_desc(next, desc);
        Some(pkt)
    }

    // -----------------------------------------------------------------------
    // Check if a TX slot is available
    // -----------------------------------------------------------------------
    fn can_send(&self) -> bool {
        let ring = self.tx_ring_va as *mut TxDesc;
        let desc = unsafe { &*ring.add(self.tx_tail) };
        fence(Ordering::SeqCst);
        self.tx_first || (desc.status & 0x01 != 0) // DD bit
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

        let ring = self.tx_ring_va as *mut TxDesc;
        let idx = self.tx_tail;
        let desc = unsafe { &mut *ring.add(idx) };

        let buf =
            unsafe { core::slice::from_raw_parts_mut(self.tx_bufs_va[idx] as *mut u8, data.len()) };
        buf.copy_from_slice(data);

        desc.addr = self.tx_bufs_pa[idx] as u64;
        desc.len = data.len() as u16;
        desc.cmd = TX_CMD_EOP | TX_CMD_IFCS | TX_CMD_RS;
        desc.status = 0;
        fence(Ordering::SeqCst);

        self.tx_tail = (idx + 1) % NUM_TX;
        unsafe { mmio_write(self.base, E1000E_TDT, self.tx_tail as u32) };
        fence(Ordering::SeqCst);

        if self.tx_tail == 0 {
            self.tx_first = false;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Handle interrupt — returns true if there was something pending
    // -----------------------------------------------------------------------
    fn handle_interrupt(&mut self) -> bool {
        let icr = unsafe { mmio_read(self.base, E1000E_ICR) };
        if icr != 0 {
            unsafe { mmio_write(self.base, E1000E_ICR, icr) };
            true
        } else {
            false
        }
    }
}

impl Drop for E1000eHw {
    fn drop(&mut self) {
        let rx_pages = (NUM_RX * size_of::<RxDesc>() + 4095) / 4096;
        let tx_pages = (NUM_TX * size_of::<TxDesc>() + 4095) / 4096;
        dealloc_dma_pages(self.rx_ring_va, rx_pages);
        dealloc_dma_pages(self.tx_ring_va, tx_pages);
        for v in &self.rx_bufs_va {
            dealloc_dma_pages(*v, 1);
        }
        for v in &self.tx_bufs_va {
            dealloc_dma_pages(*v, 1);
        }
    }
}

// ---------------------------------------------------------------------------
// Public driver wrapper
// ---------------------------------------------------------------------------
#[derive(Clone)]
pub struct E1000eDriver(Arc<Mutex<E1000eHw>>);

#[derive(Clone)]
pub struct E1000eInterface {
    iface: Arc<Mutex<Interface<'static, E1000eDriver>>>,
    driver: E1000eDriver,
    name: String,
    irq: usize,
}

impl Scheme for E1000eInterface {
    fn name(&self) -> &str {
        "e1000e"
    }

    fn handle_irq(&self, irq: usize) {
        if irq != self.irq {
            return;
        }
        let had_data = self.driver.0.lock().handle_interrupt();
        if had_data {
            let ts = Instant::from_micros(timer_now_as_micros() as i64);
            let sockets = get_sockets();
            let mut sockets = sockets.lock();
            if let Err(e) = self.iface.lock().poll(&mut sockets, ts) {
                warn!("[e1000e] poll error: {}", e);
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
        self.iface.lock().update_ip_addrs(|addrs| {
            if let Some(addr) = addrs
                .iter_mut()
                .find(|addr| matches!(addr, IpCidr::Ipv4(_)))
            {
                *addr = IpCidr::Ipv4(cidr);
            }
        });
        Ok(())
    }
    fn poll(&self) -> DeviceResult {
        let ts = Instant::from_micros(timer_now_as_micros() as i64);
        let sockets = get_sockets();
        let mut sockets = sockets.lock();
        self.iface
            .lock()
            .poll(&mut sockets, ts)
            .map(|_| ())
            .map_err(|_| DeviceError::IoError)
    }
    fn recv(&self, buf: &mut [u8]) -> DeviceResult<usize> {
        if let Some(pkt) = self.driver.0.lock().receive() {
            let n = pkt.len().min(buf.len());
            buf[..n].copy_from_slice(&pkt[..n]);
            Ok(n)
        } else {
            Err(DeviceError::NotReady)
        }
    }
    fn send(&self, data: &[u8]) -> DeviceResult<usize> {
        let mut hw = self.driver.0.lock();
        hw.send(data)?;
        Ok(data.len())
    }
}

// ---------------------------------------------------------------------------
// smoltcp Device impl
// ---------------------------------------------------------------------------
pub struct E1000eRxToken(Vec<u8>);
pub struct E1000eTxToken(E1000eDriver);

impl phy::Device<'_> for E1000eDriver {
    type RxToken = E1000eRxToken;
    type TxToken = E1000eTxToken;

    fn receive(&mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        self.0
            .lock()
            .receive()
            .map(|pkt| (E1000eRxToken(pkt), E1000eTxToken(self.clone())))
    }
    fn transmit(&mut self) -> Option<Self::TxToken> {
        if self.0.lock().can_send() {
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
    fn consume<R, F>(mut self, _ts: Instant, f: F) -> SmolResult<R>
    where
        F: FnOnce(&mut [u8]) -> SmolResult<R>,
    {
        f(&mut self.0)
    }
}

impl phy::TxToken for E1000eTxToken {
    fn consume<R, F>(self, _ts: Instant, len: usize, f: F) -> SmolResult<R>
    where
        F: FnOnce(&mut [u8]) -> SmolResult<R>,
    {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf)?;
        let mut hw = self.0 .0.lock();
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
    let rx_ring_pages = (NUM_RX * size_of::<RxDesc>() + 4095) / 4096;
    let tx_ring_pages = (NUM_TX * size_of::<TxDesc>() + 4095) / 4096;
    let (rx_ring_va, rx_ring_pa) = alloc_dma_pages(rx_ring_pages);
    let (tx_ring_va, tx_ring_pa) = alloc_dma_pages(tx_ring_pages);

    let mut rx_bufs_va = Vec::with_capacity(NUM_RX);
    let mut rx_bufs_pa = Vec::with_capacity(NUM_RX);
    let mut tx_bufs_va = Vec::with_capacity(NUM_TX);
    let mut tx_bufs_pa = Vec::with_capacity(NUM_TX);

    for _ in 0..NUM_RX {
        let (v, p) = alloc_dma_pages(BUF_SIZE / 4096);
        rx_bufs_va.push(v);
        rx_bufs_pa.push(p);
    }
    for _ in 0..NUM_TX {
        let (v, p) = alloc_dma_pages(BUF_SIZE / 4096);
        tx_bufs_va.push(v);
        tx_bufs_pa.push(p);
    }

    let mut hw = E1000eHw {
        base: vaddr,
        mac: [0u8; 6],
        rx_ring_va,
        rx_ring_pa,
        rx_bufs_va,
        rx_bufs_pa,
        rx_tail: NUM_RX - 1,
        tx_ring_va,
        tx_ring_pa,
        tx_bufs_va,
        tx_bufs_pa,
        tx_tail: 0,
        tx_head_shadow: 0,
        tx_first: true,
    };

    unsafe {
        hw.reset_and_init()?;
    }

    let mac_bytes = hw.mac;
    let hw = Arc::new(Mutex::new(hw));
    let driver = E1000eDriver(hw);

    let ethernet_addr = EthernetAddress::from_bytes(&mac_bytes);
    let ip_addrs = [IpCidr::new(IpAddress::v4(0, 0, 0, 0), 0)];
    static mut ROUTES_STORAGE: [Option<(IpCidr, Route)>; 1] = [None; 1];
    let routes = unsafe { Routes::new(&mut ROUTES_STORAGE[..]) };

    let iface = InterfaceBuilder::new(driver.clone())
        .ethernet_addr(ethernet_addr)
        .neighbor_cache(NeighborCache::new(BTreeMap::new()))
        .ip_addrs(ip_addrs)
        .routes(routes)
        .finalize();

    info!(
        "[e1000e] interface {} up, MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, awaiting IPv4 configuration",
        name, mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5]
    );

    Ok(E1000eInterface {
        iface: Arc::new(Mutex::new(iface)),
        driver,
        name,
        irq,
    })
}
