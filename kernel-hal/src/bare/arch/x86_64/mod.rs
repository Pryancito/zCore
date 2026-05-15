mod drivers;
#[cfg(feature = "graphic")]
mod early_fb_console;
mod trap;

pub mod config;
pub mod cpu;
pub mod interrupt;
pub mod mem;
pub mod timer;
pub mod vm;

#[doc(cfg(target_arch = "x86_64"))]
pub mod special;

hal_fn_impl! {
    impl mod crate::hal_fn::console {
        fn console_write_early(_s: &str) {
            #[cfg(feature = "graphic")]
            {
                // Note: this is within the kernel-hal crate, so we can reference the private
                // `imp::arch` module.
                crate::imp::arch::early_fb_console::write_str(_s);
            }
        }

        fn console_progress_early(_progress: u32) {
            #[cfg(feature = "graphic")]
            {
                crate::imp::arch::early_fb_console::draw_progress_bar(_progress);
            }
        }
    }
}

use crate::{mem::phys_to_virt, KCONFIG};
use x86_64::registers::control::{Cr4, Cr4Flags};

pub const fn timer_interrupt_vector() -> usize {
    trap::X86_INT_APIC_TIMER
}

pub fn cmdline() -> alloc::string::String {
    KCONFIG.cmdline.into()
}

pub fn init_ram_disk() -> Option<&'static mut [u8]> {
    let start = phys_to_virt(KCONFIG.initrd_start as usize);
    Some(unsafe { core::slice::from_raw_parts_mut(start as *mut u8, KCONFIG.initrd_size as usize) })
}

pub fn primary_init_early() {
    // init serial output first
    drivers::init_early().unwrap();
}

pub fn primary_init() {
    drivers::init().unwrap();
    unsafe {
        // enable global page
        Cr4::update(|f| f.insert(Cr4Flags::PAGE_GLOBAL));
    }
}

pub fn timer_init() {
    timer::init();
}

pub fn secondary_init() {
    zcore_drivers::irq::x86::Apic::init_local_apic_ap();
}
