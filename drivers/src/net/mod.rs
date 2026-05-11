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
    *MSI_IRQ_HOST.lock() = Some(irq);
}

pub fn pci_note_pending_msi(vector: usize, dev: Arc<dyn Scheme>) {
    MSI_PENDING.lock().push((vector, dev));
}

pub fn pci_finish_msi_registrations() -> DeviceResult {
    let host = MSI_IRQ_HOST.lock().clone();
    if let Some(host) = host {
        let mut q = MSI_PENDING.lock();
        for (v, d) in q.drain(..) {
            match host.register_device(v, d) {
                Ok(_) => {
                    warn!("[net] successfully registered device for vector {}", v);
                    let _ = host.unmask(v);
                }
                Err(e) => warn!("[net] failed to register device for vector {}: {:?}", v, e),
            }
        }
    }
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

extern "C" {
    fn drivers_dma_alloc(pages: usize) -> PhysAddr;
    fn drivers_dma_dealloc(paddr: PhysAddr, pages: usize) -> i32;
    fn drivers_phys_to_virt(paddr: PhysAddr) -> VirtAddr;
    fn drivers_virt_to_phys(vaddr: VirtAddr) -> PhysAddr;
    fn drivers_timer_now_as_micros() -> u64;
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
    *PACKET_CALLBACK.lock() = Some(callback);
}

/// Dispatches a received packet to the registered callback.
pub fn net_dispatch_packet(packet: &[u8]) {
    if let Some(callback) = *PACKET_CALLBACK.lock() {
        callback(packet);
    }
}

// 注意！这个容易出现死锁
pub fn get_sockets() -> Arc<Mutex<SocketSet<'static>>> {
    SOCKETS.clone()
}
