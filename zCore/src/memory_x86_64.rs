//! Define physical frame allocation and dynamic memory allocation.

use bitmap_allocator::BitAlloc;
use core::ops::Range;
use kernel_hal::PhysAddr;
use core::sync::atomic::{AtomicUsize, Ordering};
use lock::Mutex;

static TOTAL_MEMORY: AtomicUsize = AtomicUsize::new(0);
static USED_MEMORY: AtomicUsize = AtomicUsize::new(0);



type FrameAlloc = bitmap_allocator::BitAlloc16M; // max 64G

const PAGE_BITS: usize = 12;
const MAX_MANAGED_PADDR_EXCLUSIVE: PhysAddr = 1usize << (PAGE_BITS + 24); // 64GiB

/// Global physical frame allocator
static FRAME_ALLOCATOR: Mutex<FrameAlloc> = Mutex::new(FrameAlloc::DEFAULT);

#[inline]
fn phys_addr_to_frame_idx(addr: PhysAddr) -> usize {
    addr >> PAGE_BITS
}

#[inline]
fn frame_idx_to_phys_addr(idx: usize) -> PhysAddr {
    idx << PAGE_BITS
}

pub fn insert_regions(regions: &[Range<PhysAddr>]) {
    debug!("init_frame_allocator regions: {regions:x?}");
    let mut ba = FRAME_ALLOCATOR.lock();
    for region in regions {
        let start = region.start.min(MAX_MANAGED_PADDR_EXCLUSIVE);
        let end = region.end.min(MAX_MANAGED_PADDR_EXCLUSIVE);
        if end <= start {
            continue;
        }
        if end != region.end {
            crate::klog_warn!(
                "memory: frame allocator region clipped (>64GiB): {:#x?} -> {:#x?}",
                region,
                start..end
            );
        }
        let frame_start = phys_addr_to_frame_idx(start);
        let frame_end = phys_addr_to_frame_idx(end - 1) + 1;
        if frame_start < frame_end {
            ba.insert(frame_start..frame_end);
            TOTAL_MEMORY.fetch_add(frame_idx_to_phys_addr(frame_end - frame_start), Ordering::Relaxed);
            let range_start = frame_idx_to_phys_addr(frame_start);
            let range_end = frame_idx_to_phys_addr(frame_end);
            let mib = (range_end - range_start) / (1024 * 1024);
            crate::klog_info!(
                "memory: free RAM range {:#x}..{:#x} ({} MiB)",
                range_start,
                range_end,
                mib
            );
        }
    }
    let (used, total) = stats();
    crate::klog_info!(
        "memory: frame allocator ready ({} MiB managed, {} KiB used)",
        total / (1024 * 1024),
        used / 1024
    );
}

pub fn frame_alloc(frame_count: usize, align_log2: usize) -> Option<PhysAddr> {
    let ret = FRAME_ALLOCATOR
        .lock()
        .alloc_contiguous(frame_count, align_log2)
        .map(frame_idx_to_phys_addr);
    if ret.is_some() {
        USED_MEMORY.fetch_add(frame_count << PAGE_BITS, Ordering::Relaxed);
    }
    trace!(
        "frame_alloc_contiguous(): {ret:x?} ~ {end_ret:x?}, align_log2={align_log2}",
        end_ret = ret.map(|x| x + frame_count),
    );
    ret
}

pub fn frame_dealloc(target: PhysAddr) {
    trace!("frame_dealloc(): {target:x}");
    USED_MEMORY.fetch_sub(1 << PAGE_BITS, Ordering::Relaxed);
    FRAME_ALLOCATOR
        .lock()
        .dealloc(phys_addr_to_frame_idx(target))
}

pub fn stats() -> (usize, usize) {
    let used = USED_MEMORY.load(Ordering::Relaxed);
    let total = TOTAL_MEMORY.load(Ordering::Relaxed);
    (used, total)
}

cfg_if! {
    if #[cfg(not(feature = "libos"))] {
        use buddy_system_allocator::Heap;
        use core::{
            alloc::{GlobalAlloc, Layout},
            ops::Deref,
            ptr::NonNull,
        };

        const KERNEL_HEAP_SIZE: usize = 16 * 1024 * 1024; // 16 MB
        const ORDER: usize = 32;

        /// Global heap allocator
        ///
        /// Available after `memory::init()`.
        #[global_allocator]
        static HEAP_ALLOCATOR: LockedHeap<ORDER> = LockedHeap::<ORDER>::new();

        /// Initialize the global heap allocator.
        pub fn init() {
            const MACHINE_ALIGN: usize = core::mem::size_of::<usize>();
            const HEAP_BLOCK: usize = KERNEL_HEAP_SIZE / MACHINE_ALIGN;
            static mut HEAP: [usize; HEAP_BLOCK] = [0; HEAP_BLOCK];
            let heap_start = core::ptr::addr_of_mut!(HEAP).cast::<u8>() as usize;
            unsafe {
                HEAP_ALLOCATOR
                    .lock()
                    .init(heap_start, HEAP_BLOCK * MACHINE_ALIGN);
            }
            crate::klog_info!(
                "memory: kernel heap ready ({} KiB @ {:#x})",
                KERNEL_HEAP_SIZE / 1024,
                heap_start
            );
        }

        pub struct LockedHeap<const ORDER: usize>(Mutex<Heap<ORDER>>);

        impl<const ORDER: usize> LockedHeap<ORDER> {
            /// Creates an empty heap
            pub const fn new() -> Self {
                LockedHeap(Mutex::new(Heap::<ORDER>::new()))
            }
        }

        impl<const ORDER: usize> Deref for LockedHeap<ORDER> {
            type Target = Mutex<Heap<ORDER>>;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        unsafe impl<const ORDER: usize> GlobalAlloc for LockedHeap<ORDER> {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
                self.0
                    .lock()
                    .alloc(layout)
                    .ok()
                    .map_or(core::ptr::null_mut::<u8>(), |allocation| {
                        USED_MEMORY.fetch_add(layout.size(), Ordering::Relaxed);
                        allocation.as_ptr()
                    })
            }

            unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
                USED_MEMORY.fetch_sub(layout.size(), Ordering::Relaxed);
                self.0.lock().dealloc(NonNull::new_unchecked(ptr), layout)
            }
        }
    } else {
        pub fn init() {}
    }
}

#[cfg(feature = "hypervisor")]
mod rvm_extern_fn {
    use super::*;

    #[rvm::extern_fn(alloc_frame)]
    fn rvm_alloc_frame() -> Option<usize> {
        hal_frame_alloc()
    }

    #[rvm::extern_fn(dealloc_frame)]
    fn rvm_dealloc_frame(paddr: usize) {
        hal_frame_dealloc(&paddr)
    }

    #[rvm::extern_fn(phys_to_virt)]
    fn rvm_phys_to_virt(paddr: usize) -> usize {
        // 示意，这个常量已经没了
        // pub const PHYSICAL_MEMORY_OFFSET: usize = KERNEL_OFFSET - PHYS_MEMORY_BASE;
        paddr + PHYSICAL_MEMORY_OFFSET
    }

    #[cfg(target_arch = "x86_64")]
    #[rvm::extern_fn(is_host_timer_interrupt)]
    fn rvm_is_host_timer_interrupt(vector: u8) -> bool {
        vector == 32 // IRQ0 + Timer in kernel-hal-bare/src/arch/x86_64/interrupt.rs
    }

    #[cfg(target_arch = "x86_64")]
    #[rvm::extern_fn(is_host_serial_interrupt)]
    fn rvm_is_host_serial_interrupt(vector: u8) -> bool {
        vector == 36 // IRQ0 + COM1 in kernel-hal-bare/src/arch/x86_64/interrupt.rs
    }
}
