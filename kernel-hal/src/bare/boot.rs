//! Bootstrap and initialization.

use crate::{KernelConfig, KernelHandler, KCONFIG, KHANDLER};

hal_fn_impl! {
    impl mod crate::hal_fn::boot {
        fn cmdline() -> alloc::string::String {
            super::arch::cmdline()
        }

        fn init_ram_disk() -> Option<&'static mut [u8]> {
            super::arch::init_ram_disk()
        }

        fn primary_init_early(cfg: KernelConfig, handler: &'static impl KernelHandler) {
            KCONFIG.init_once_by(cfg);
            KHANDLER.init_once_by(handler);
            crate::klog_info!("Eclipse: primary CPU {} init early", crate::cpu::cpu_id());
            super::arch::primary_init_early();
        }

        fn primary_init() {
            crate::klog_info!("Eclipse: primary CPU {} init", crate::cpu::cpu_id());
            unsafe { trapframe::init() };
            super::arch::primary_init();
        }

        fn secondary_init() {
            // info!("Secondary CPU {} init...", crate::cpu::cpu_id());
            // we can't print anything here, see reason: zcore/main.rs::secondary_main()
            unsafe { trapframe::init() };
            super::arch::secondary_init();
            // now can print
        }
    }
}
