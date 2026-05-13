//! CPU information.

use raw_cpuid::CpuId;

hal_fn_impl! {
    impl mod crate::hal_fn::cpu {
        fn cpu_id() -> u8 {
            CpuId::new()
                .get_feature_info()
                .unwrap()
                .initial_local_apic_id() as u8
        }

        fn cpu_frequency() -> u16 {
            static CPU_FREQ_MHZ: spin::Once<u16> = spin::Once::new();
            *CPU_FREQ_MHZ.call_once(|| {
                const DEFAULT: u16 = 4000;
                CpuId::new()
                    .get_processor_frequency_info()
                    .map(|info| info.processor_base_frequency())
                    .unwrap_or(DEFAULT)
                    .max(DEFAULT)
            })
        }

        fn reset() -> ! {
            info!("resetting/shutting down...");
            use zcore_drivers::io::{Io, Pmio};

            // Method 1: PS/2 Controller (Keyboard Controller)
            // Writing 0xFE to port 0x64 triggers a pulse on the reset line.
            Pmio::<u8>::new(0x64).write(0xFE);

            // Method 2: PCI Reset Control Register (standard on many chipsets)
            // Port 0xCF9. 0x06 = system reset, 0x0E = hard reset.
            Pmio::<u8>::new(0xCF9).write(0x06);
            Pmio::<u8>::new(0xCF9).write(0x0E);

            // Method 3: QEMU/ACPI Poweroff (fallback for halt/poweroff)
            Pmio::<u16>::new(0x604).write(0x2000);

            // Method 4: Triple Fault (the "nuclear" option)
            // Load a zero-length IDT and trigger an interrupt.
            unsafe {
                let idtr: [u16; 5] = [0, 0, 0, 0, 0];
                core::arch::asm!("lidt [{}]", in(reg) &idtr);
                core::arch::asm!("int3");
            }

            loop {
                super::interrupt::wait_for_interrupt();
            }
        }
    }
}
