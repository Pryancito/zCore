//! LAN driver, only for Realtek currently.
#![allow(unused)]

use alloc::{sync::Arc, vec};
use lock::Mutex;
use smoltcp::socket::SocketSet;

pub mod e1000;
pub mod e1000e;
// pub mod ixgbe;
pub mod loopback;
pub use isomorphic_drivers::provider::Provider;
pub use loopback::LoopbackInterface;

use crate::scheme::{IrqScheme, Scheme};
use crate::DeviceResult;
use alloc::vec::Vec;

static MSI_IRQ_HOST: Mutex<Option<Arc<dyn IrqScheme>>> = Mutex::new(None);
static MSI_PENDING: Mutex<Vec<(usize, Arc<dyn Scheme>)>> = Mutex::new(Vec::new());

pub fn pci_set_irq_host(irq: Arc<dyn IrqScheme>) {
    let flag = intr_get();
    if flag { intr_off(); }
    *MSI_IRQ_HOST.lock() = Some(irq);
    if flag { intr_on(); }
}

pub fn pci_note_pending_msi(vector: usize, dev: Arc<dyn Scheme>) {
    let flag = intr_get();
    if flag { intr_off(); }
    MSI_PENDING.lock().push((vector, dev));
    if flag { intr_on(); }
}

pub fn pci_finish_msi_registrations() -> DeviceResult {
    let flag = intr_get();
    if flag { intr_off(); }
    
    let host = MSI_IRQ_HOST.lock().clone();
    if let Some(host) = host {
        let mut q = MSI_PENDING.lock();
        for (v, d) in q.drain(..) {
            match host.register_device(v, d) {
                Ok(_) => {
                    crate::klog_info!("[net] IRQ vector {} registered for NIC", v);
                    let _ = host.unmask(v);
                }
                Err(e) => crate::klog_warn!(
                    "[net] failed to register IRQ vector {}: {:?}",
                    v,
                    e
                ),
            }
        }
    }
    
    if flag { intr_on(); }
    Ok(())
}

cfg_if::cfg_if! {
    if #[cfg(target_arch = "riscv64")] {
mod realtek;
mod rtlx;

pub use rtlx::*;
    }
}

/*
/// External functions that drivers must use
pub trait Provider {
    /// Page size (usually 4K)
    const PAGE_SIZE: usize;

    /// Allocate consequent physical memory for DMA.
    /// Return (`virtual address`, `physical address`).
    /// The address is page aligned.
    fn alloc_dma(size: usize) -> (usize, usize);

    /// Deallocate DMA
    fn dealloc_dma(vaddr: usize, size: usize);
}
*/

pub struct ProviderImpl;

impl Provider for ProviderImpl {
    const PAGE_SIZE: usize = PAGE_SIZE;

    fn alloc_dma(size: usize) -> (usize, usize) {
        let paddr = unsafe { drivers_dma_alloc(size / PAGE_SIZE) };
        let vaddr = phys_to_virt(paddr);
        (vaddr, paddr)
    }

    fn dealloc_dma(vaddr: usize, size: usize) {
        let paddr = virt_to_phys(vaddr);
        unsafe { drivers_dma_dealloc(paddr, size / PAGE_SIZE) };
    }
}

pub fn phys_to_virt(paddr: PhysAddr) -> VirtAddr {
    unsafe { drivers_phys_to_virt(paddr) }
}

pub fn virt_to_phys(vaddr: VirtAddr) -> PhysAddr {
    unsafe { drivers_virt_to_phys(vaddr) }
}

pub fn timer_now_as_micros() -> u64 {
    unsafe { drivers_timer_now_as_micros() }
}

pub fn intr_on() {
    unsafe { drivers_intr_on() }
}

pub fn intr_off() {
    unsafe { drivers_intr_off() }
}

pub fn intr_get() -> bool {
    unsafe { drivers_intr_get() }
}

extern "C" {
    fn drivers_dma_alloc(pages: usize) -> PhysAddr;
    fn drivers_dma_dealloc(paddr: PhysAddr, pages: usize) -> i32;
    fn drivers_phys_to_virt(paddr: PhysAddr) -> VirtAddr;
    fn drivers_virt_to_phys(vaddr: VirtAddr) -> PhysAddr;
    fn drivers_timer_now_as_micros() -> u64;
    fn drivers_intr_on();
    fn drivers_intr_off();
    fn drivers_intr_get() -> bool;
}

pub const PAGE_SIZE: usize = 4096;

type VirtAddr = usize;
type PhysAddr = usize;

lazy_static::lazy_static! {
    pub static ref SOCKETS: Arc<Mutex<SocketSet<'static>>> =
    Arc::new(Mutex::new(SocketSet::new(vec![])));

    static ref PACKET_CALLBACK: Mutex<Option<fn(&[u8])>> = Mutex::new(None);
}

/// Sets a callback for every received packet (raw).
pub fn set_packet_callback(callback: fn(&[u8])) {
    let flag = intr_get();
    if flag { intr_off(); }
    *PACKET_CALLBACK.lock() = Some(callback);
    if flag { intr_on(); }
}

/// Dispatches a received packet to the registered callback.
pub fn net_dispatch_packet(data: &[u8]) {
    warn!("[net] dispatching packet of {} bytes to callback", data.len());
    let flag = intr_get();
    if flag { intr_off(); }
    
    if let Some(callback) = PACKET_CALLBACK.lock().as_ref() {
        callback(data);
    }
    
    if flag { intr_on(); }
}

// 注意！这个容易出现死锁
pub fn get_sockets() -> Arc<Mutex<SocketSet<'static>>> {
    SOCKETS.clone()
}
