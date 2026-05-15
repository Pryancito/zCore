use alloc::{boxed::Box, sync::Arc};

#[cfg(feature = "graphic")]
use alloc::format;

use zcore_drivers::irq::x86::Apic;
use zcore_drivers::scheme::IrqScheme;
use zcore_drivers::uart::{BufferedUart, Uart16550Pmio};
use zcore_drivers::{Device, DeviceResult};

use super::trap;
use crate::drivers;

pub(super) fn init_early() -> DeviceResult {
    let uart = Arc::new(Uart16550Pmio::new(0x3F8));
    drivers::add_device(Device::Uart(BufferedUart::new(uart)));
    let uart = Arc::new(Uart16550Pmio::new(0x2F8));
    drivers::add_device(Device::Uart(BufferedUart::new(uart)));
    Ok(())
}

fn boot_progress(p: u32) {
    #[cfg(feature = "graphic")]
    crate::console::early_progress_bar(p);
    #[cfg(not(feature = "graphic"))]
    let _ = p;
}

pub(super) fn init() -> DeviceResult {
    boot_progress(81);
    zcore_drivers::init();
    boot_progress(82);
    Apic::init_local_apic_bsp(crate::mem::phys_to_virt);
    let irq = Arc::new(Apic::new(
        super::special::pc_firmware_tables().0 as usize,
        crate::mem::phys_to_virt,
    ));
    let uarts = drivers::all_uart();
    if let Some(u) = uarts.try_get(0) {
        irq.register_device(trap::X86_ISA_IRQ_COM1, u.clone().upcast())?;
        irq.unmask(trap::X86_ISA_IRQ_COM1)?;

        if let Some(u) = uarts.try_get(1) {
            irq.register_device(trap::X86_ISA_IRQ_COM2, u.clone().upcast())?;
            irq.unmask(trap::X86_ISA_IRQ_COM2)?;
        }
    }

    use x2apic::lapic::{TimerDivide, TimerMode};

    irq.register_local_apic_handler(trap::X86_INT_APIC_TIMER, Box::new(super::trap::super_timer))?;

    if Apic::local_apic_ready() {
        // SAFETY: called once on BSP during primary_init
        let lapic = Apic::local_apic();
        lapic.set_timer_mode(TimerMode::Periodic);
        lapic.set_timer_divide(TimerDivide::Div256); // indeed it is Div1, the name is confusing.
        let cycles =
            super::cpu::cpu_frequency() as u64 * 1_000_000 / super::super::timer::TICKS_PER_SEC;
        lapic.set_timer_initial(cycles as u32);
        lapic.disable_timer();
    } else {
        crate::klog_warn!("[drivers] LAPIC unavailable — APIC timer left disabled");
    }

    #[cfg(all(not(feature = "no-pci"), feature = "xhci-usb-hid"))]
    {
        use zcore_drivers::usb::xhci_hid;
        let irq_apic: Arc<dyn zcore_drivers::scheme::IrqScheme> = irq.clone();
        xhci_hid::pci_set_irq_host(irq_apic);
    }

    drivers::add_device(Device::Irq(irq.clone()));
    boot_progress(83);

    #[cfg(not(feature = "no-pci"))]
    {
        // PCI scan
        use crate::vm::{GenericPageTable, PageTable};
        use crate::{CachePolicy, MMUFlags, PhysAddr, VirtAddr};
        use zcore_drivers::builder::IoMapper;
        use zcore_drivers::bus::pci;

        struct IoMapperImpl;
        impl IoMapper for IoMapperImpl {
            fn query_or_map(&self, paddr: PhysAddr, size: usize) -> Option<VirtAddr> {
                let vaddr = crate::mem::phys_to_virt(paddr);
                let mut pt = PageTable::from_current();

                if let Ok((paddr_mapped, _, _)) = pt.query(vaddr) {
                    if paddr_mapped == paddr {
                        return Some(vaddr);
                    }
                }

                let size = (size + 0xfff) & !0xfff;
                let flags = MMUFlags::READ
                    | MMUFlags::WRITE
                    | MMUFlags::DEVICE
                    | MMUFlags::from_bits_truncate(CachePolicy::UncachedDevice as usize);

                warn!(
                    "[xhci] Mapeando BAR PCI en PT kernel: {:#x} -> {:#x} (size: {:#x})",
                    paddr, vaddr, size
                );
                if let Err(e) = pt.map_cont(vaddr, size, paddr, flags) {
                    crate::klog_err!("[xhci] failed to map PCI BAR: {:?}", e);
                    return None;
                }

                core::mem::forget(pt);
                Some(vaddr)
            }
        }

        // Pass boot framebuffer info to display drivers for native resolution inheritance
        #[cfg(feature = "graphic")]
        {
            use crate::KCONFIG;
            let (width, height) = KCONFIG.fb_mode.resolution();
            let stride = KCONFIG.fb_mode.stride();
            zcore_drivers::display::set_boot_fb_info(
                KCONFIG.fb_addr,
                width as u32,
                height as u32,
                (stride * 4) as u32,
            );
        }

        boot_progress(84);
        let pci_devs = pci::init(Some(Arc::new(IoMapperImpl)))?;
        boot_progress(87);
        for d in pci_devs.into_iter() {
            drivers::add_device(d);
        }

        // Finish MSI registrations for USB
        #[cfg(feature = "xhci-usb-hid")]
        {
            use zcore_drivers::usb::xhci_hid;
            let _ = xhci_hid::pci_finish_msi_registrations();
        }

        // Finish MSI registrations for Net
        {
            use zcore_drivers::net;
            net::pci_set_irq_host(irq.clone());
            let _ = net::pci_finish_msi_registrations();
        }
    }

    boot_progress(88);

    #[cfg(feature = "graphic")]
    let graphics_console_note = {
        use alloc::string::String;
        if let Some(display) = crate::drivers::all_display().first() {
            crate::console::init_graphic_console(display.clone());
            let _ = display.need_flush();
            let info = display.info();
            Some(format!(
                "{} {}x{}",
                display.name(),
                info.width,
                info.height
            ))
        } else {
            use crate::KCONFIG;
            use zcore_drivers::display::UefiDisplay;
            use zcore_drivers::prelude::{ColorFormat, DisplayInfo};

            let (width, height) = KCONFIG.fb_mode.resolution();
            let stride = KCONFIG.fb_mode.stride();
            if KCONFIG.fb_addr == 0 || width == 0 || height == 0 {
                crate::klog_warn!(
                    "[drivers] no framebuffer from bootloader (fb_addr={:#x}, {}x{}) — skipping graphic console",
                    KCONFIG.fb_addr, width, height
                );
                Some(String::from("unavailable (no bootloader framebuffer)"))
            } else {
                let display = Arc::new(UefiDisplay::new(DisplayInfo {
                    width: width as _,
                    height: height as _,
                    pitch: (stride * 4) as u32,
                    format: ColorFormat::ARGB8888,
                    fb_base_vaddr: crate::mem::phys_to_virt(KCONFIG.fb_addr as usize),
                    fb_size: KCONFIG.fb_size as usize,
                }));
                crate::drivers::add_device(Device::Display(display.clone()));
                crate::console::init_graphic_console(display.clone());
                Some(format!("uefi-gop {}x{}", width, height))
            }
        }
    };

    #[cfg(not(feature = "graphic"))]
    let graphics_console_note: Option<alloc::string::String> = None;

    drivers::klog_graphics_device_summary(graphics_console_note.as_deref());

    #[cfg(feature = "loopback")]
    {
        use crate::net;
        net::init();
    }

    crate::klog_info!("Eclipse: drivers init complete");
    Ok(())
}
