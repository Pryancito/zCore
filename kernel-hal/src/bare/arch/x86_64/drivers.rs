use alloc::{boxed::Box, sync::Arc};

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

pub(super) fn init() -> DeviceResult {
    zcore_drivers::init();
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

    // SAFETY: this will be called once and only once for every core
    Apic::local_apic().set_timer_mode(TimerMode::Periodic);
    Apic::local_apic().set_timer_divide(TimerDivide::Div256); // indeed it is Div1, the name is confusing.
    let cycles =
        super::cpu::cpu_frequency() as u64 * 1_000_000 / super::super::timer::TICKS_PER_SEC;
    Apic::local_apic().set_timer_initial(cycles as u32);
    Apic::local_apic().disable_timer();

    #[cfg(all(not(feature = "no-pci"), feature = "xhci-usb-hid"))]
    {
        use zcore_drivers::usb::xhci_hid;
        let irq_apic: Arc<dyn zcore_drivers::scheme::IrqScheme> = irq.clone();
        xhci_hid::pci_set_irq_host(irq_apic);
    }

    drivers::add_device(Device::Irq(irq.clone()));

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
                    warn!("[xhci] Error crítico al mapear BAR: {:?}", e);
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

        let pci_devs = pci::init(Some(Arc::new(IoMapperImpl)))?;
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

    #[cfg(feature = "graphic")]
    {
        // If display was already created in init_early(), just hook up the graphic console.
        // Otherwise create it here (fallback).
        if let Some(display) = crate::drivers::all_display().first() {
            crate::console::init_graphic_console(display.clone());
            // VirtIO GPU (and similar) needs an explicit flush to push framebuffer
            // contents to the screen.  Spawn a periodic flush task matching
            // what the RISC-V init already does.
            if display.need_flush() {
                crate::thread::spawn(crate::common::future::DisplayFlushFuture::new(
                    display, 30,
                ));
            }
        } else {
            use crate::KCONFIG;
            use zcore_drivers::display::UefiDisplay;
            use zcore_drivers::prelude::{ColorFormat, DisplayInfo};

            let (width, height) = KCONFIG.fb_mode.resolution();
            let stride = KCONFIG.fb_mode.stride();
            let display = Arc::new(UefiDisplay::new(DisplayInfo {
                width: width as _,
                height: height as _,
                pitch: (stride * 4) as u32,
                format: ColorFormat::ARGB8888, // uefi::proto::console::gop::PixelFormat::Bgr
                fb_base_vaddr: crate::mem::phys_to_virt(KCONFIG.fb_addr as usize),
                fb_size: KCONFIG.fb_size as usize,
            }));
            crate::drivers::add_device(Device::Display(display.clone()));
            crate::console::init_graphic_console(display.clone());
        }
    }

    #[cfg(feature = "loopback")]
    {
        use crate::net;
        net::init();
    }

    info!("Drivers init end.");
    Ok(())
}
