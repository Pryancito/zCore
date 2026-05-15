//! DMA memory region allocator.
//!
//! Provides page-aligned DMA-capable buffers backed by the kernel DMA allocator
//! (`drivers_dma_alloc`).  Physical and virtual addresses are tracked so that
//! hardware registers can be programmed with the physical address while the CPU
//! accesses data through the virtual address.

use crate::bus::PAGE_SIZE;

extern "C" {
    fn drivers_dma_alloc(pages: usize) -> usize;
    fn drivers_dma_dealloc(paddr: usize, pages: usize) -> i32;
    fn drivers_phys_to_virt(paddr: usize) -> usize;
}

/// A contiguous, page-aligned DMA memory region.
pub struct DmaRegion {
    virt: usize,
    phys: usize,
    pages: usize,
}

impl DmaRegion {
    /// Allocate `len` bytes of DMA-capable memory, zero-filled.
    pub fn alloc(len: usize) -> Option<Self> {
        Self::alloc_inner(len, true)
    }

    /// Allocate without zeroing. Use for RX buffers filled by device DMA: zeroing
    /// dirties the cache and breaks coherency on x86 unless mappings are UC.
    pub fn alloc_uninit(len: usize) -> Option<Self> {
        Self::alloc_inner(len, false)
    }

    fn alloc_inner(len: usize, zero: bool) -> Option<Self> {
        if len == 0 {
            return None;
        }
        let pages = (len + PAGE_SIZE - 1) / PAGE_SIZE;
        let phys = unsafe { drivers_dma_alloc(pages) };
        if phys == 0 {
            return None;
        }
        let virt = unsafe { drivers_phys_to_virt(phys) };
        if zero {
            unsafe { core::ptr::write_bytes(virt as *mut u8, 0, pages * PAGE_SIZE) };
        }
        Some(Self { virt, phys, pages })
    }

    /// Virtual (CPU-accessible) base address of the region.
    #[inline]
    pub fn vaddr(&self) -> usize {
        self.virt
    }

    /// Physical (device-accessible) base address of the region.
    #[inline]
    pub fn paddr(&self) -> usize {
        self.phys
    }

    /// Return a raw pointer to the start of the region cast to `*mut T`.
    #[inline]
    pub fn as_ptr<T>(&self) -> *mut T {
        self.virt as *mut T
    }
}

impl Drop for DmaRegion {
    fn drop(&mut self) {
        if self.phys != 0 {
            unsafe { drivers_dma_dealloc(self.phys, self.pages) };
        }
    }
}
