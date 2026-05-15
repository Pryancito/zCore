//! Console input and output.

use crate::drivers;
use core::fmt::{Arguments, Result, Write};
use core::sync::atomic::{AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// Kernel log (dmesg) callback
// ---------------------------------------------------------------------------
// The `zcore` crate owns the actual ring buffer; it registers function
// pointers here so that `linux-syscall` can call `klog_read` / `klog_buf_size`
// without a direct crate dependency on `zcore`.

static KLOG_READ_FN:  AtomicUsize = AtomicUsize::new(0);
static KLOG_SIZE_FN:  AtomicUsize = AtomicUsize::new(0);
static KLOG_EMIT_FN: AtomicUsize = AtomicUsize::new(0);

/// Called once by `zcore` at startup to register the ring-buffer accessors.
pub fn klog_register(
    read_fn:  fn(&mut [u8]) -> usize,
    size_fn:  fn() -> usize,
    emit_fn:  fn(u8, &str),
) {
    KLOG_READ_FN.store(read_fn as usize, Ordering::SeqCst);
    KLOG_SIZE_FN.store(size_fn as usize, Ordering::SeqCst);
    KLOG_EMIT_FN.store(emit_fn as usize, Ordering::SeqCst);
}

/// Copy the kernel log ring buffer into `dst`.  Returns bytes written.
/// Returns 0 if no callback has been registered yet.
pub fn klog_read(dst: &mut [u8]) -> usize {
    let p = KLOG_READ_FN.load(Ordering::SeqCst);
    if p == 0 { return 0; }
    let f: fn(&mut [u8]) -> usize = unsafe { core::mem::transmute(p) };
    f(dst)
}

/// Total bytes currently stored in the kernel log ring buffer.
pub fn klog_buf_size() -> usize {
    let p = KLOG_SIZE_FN.load(Ordering::SeqCst);
    if p == 0 { return 0; }
    let f: fn() -> usize = unsafe { core::mem::transmute(p) };
    f()
}

/// Syslog priorities (Linux `syslog.h`).
pub const LOG_ERR: u8 = 3;
pub const LOG_WARNING: u8 = 4;
pub const LOG_INFO: u8 = 6;

/// Append a vital kernel message to the dmesg ring buffer (syslog priority 0–7).
/// Always recorded regardless of the `log` crate max level.
pub fn klog_emit(priority: u8, msg: &str) {
    let p = KLOG_EMIT_FN.load(Ordering::SeqCst);
    if p == 0 {
        return;
    }
    let f: fn(u8, &str) = unsafe { core::mem::transmute(p) };
    f(priority, msg);
}



struct SerialWriter;

static SERIAL_WRITER: spin::Mutex<SerialWriter> = spin::Mutex::new(SerialWriter);

impl Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> Result {
        if let Some(uart) = drivers::all_uart().first() {
            uart.write_str(s).unwrap();
            #[cfg(feature = "graphic")]
            if GRAPHIC_CONSOLE.try_get().is_none() {
                crate::hal_fn::console::console_write_early(s);
            }
        } else {
            crate::hal_fn::console::console_write_early(s);
        }
        Ok(())
    }
}

struct DebugWriter;

static DEBUG_WRITER: spin::Mutex<DebugWriter> = spin::Mutex::new(DebugWriter);

impl Write for DebugWriter {
    fn write_str(&mut self, s: &str) -> Result {
        crate::hal_fn::console::console_write_early(s);
        Ok(())
    }
}

cfg_if! {
    if #[cfg(feature = "graphic")] {
        use crate::utils::init_once::InitOnce;
        use alloc::sync::Arc;
        use core::sync::atomic::AtomicBool;
        use zcore_drivers::{scheme::DisplayScheme, utils::GraphicConsole};

        static GRAPHIC_CONSOLE: InitOnce<spin::Mutex<GraphicConsole>> = InitOnce::new();
        static CONSOLE_WIN_SIZE: InitOnce<ConsoleWinSize> = InitOnce::new();
        static GRAPHIC_DISPLAY: InitOnce<Arc<dyn DisplayScheme>> = InitOnce::new();
        static CLEAR_ON_NEXT_GRAPHIC_WRITE: AtomicBool = AtomicBool::new(false);

        pub(crate) fn init_graphic_console(display: Arc<dyn DisplayScheme>) {
            let info = display.info();
            GRAPHIC_DISPLAY.init_once_by(display.clone());
            let cons = GraphicConsole::new(display);
            let winsz = ConsoleWinSize {
                ws_row: cons.rows() as u16,
                ws_col: cons.columns() as u16,
                ws_xpixel: info.width as u16,
                ws_ypixel: info.height as u16,
            };
            CONSOLE_WIN_SIZE.init_once_by(winsz);
            GRAPHIC_CONSOLE.init_once_by(spin::Mutex::new(cons));
            // Make boot UX robust on real hardware: clear once on first graphic write
            // even if userspace/loader ordering differs.
            CLEAR_ON_NEXT_GRAPHIC_WRITE.store(true, Ordering::SeqCst);
        }

        /// Request a one-shot clear-to-black of the graphic console before the next write.
        pub fn request_clear_graphic_on_next_write() {
            // Finalize the boot progress indicator before switching to a cleared
            // native graphic console.
            crate::hal_fn::console::console_progress_early(100);
            CLEAR_ON_NEXT_GRAPHIC_WRITE.store(true, Ordering::SeqCst);
        }

        fn maybe_clear_graphic_before_write() {
            if !CLEAR_ON_NEXT_GRAPHIC_WRITE.swap(false, Ordering::SeqCst) {
                return;
            }
            if let (Some(display), Some(cons)) = (GRAPHIC_DISPLAY.try_get(), GRAPHIC_CONSOLE.try_get())
            {
                // Clear to black with opaque alpha (ARGB8888) and reset the console state.
                let _ = crate::boot_logo::clear_screen(
                    &**display,
                    zcore_drivers::prelude::RgbColor::new(0, 0, 0),
                );
                *cons.lock() = GraphicConsole::new(display.clone());  // spin::Mutex — IRQs stay enabled
            }
        }
    }
}

/// Request a one-shot clear-to-black of the graphic console before the next write.
///
/// When `feature="graphic"` is disabled, this is a no-op.
#[cfg(not(feature = "graphic"))]
pub fn request_clear_graphic_on_next_write() {
    crate::hal_fn::console::console_progress_early(100);
}

/// Writes a string slice into the serial.
pub fn serial_write_str(s: &str) {
    if let Some(mut w) = SERIAL_WRITER.try_lock() {
        let _ = w.write_str(s);
    }
}

/// Writes formatted data into the serial.
pub fn serial_write_fmt(fmt: Arguments) {
    if let Some(mut w) = SERIAL_WRITER.try_lock() {
        let _ = w.write_fmt(fmt);
    }
}

/// Writes a string slice into the serial through sbi call.
pub fn debug_write_str(s: &str) {
    if let Some(mut w) = DEBUG_WRITER.try_lock() {
        let _ = w.write_str(s);
    }
}

/// Writes formatted data into the serial through sbi call..
pub fn debug_write_fmt(fmt: Arguments) {
    if let Some(mut w) = DEBUG_WRITER.try_lock() {
        let _ = w.write_fmt(fmt);
    }
}

/// Draw a boot progress bar on the early framebuffer console (UEFI GOP), if available.
///
/// This is intended for very early boot stages before the native graphic driver exists.
pub fn early_progress_bar(progress: u32) {
    crate::hal_fn::console::console_progress_early(progress);
}

/// Writes a string slice into the graphic console.
#[allow(unused_variables)]
pub fn graphic_console_write_str(s: &str) {
    #[cfg(feature = "graphic")]
    if let Some(cons) = GRAPHIC_CONSOLE.try_get() {
        maybe_clear_graphic_before_write();
        // Use try_lock to avoid deadlock if an IRQ tries to log while 
        // the console is scrolling.
        if let Some(mut g) = cons.try_lock() {
            let _ = g.write_str(s);
        }
    }
}

/// Writes formatted data into the graphic console.
#[allow(unused_variables)]
pub fn graphic_console_write_fmt(fmt: Arguments) {
    #[cfg(feature = "graphic")]
    if let Some(cons) = GRAPHIC_CONSOLE.try_get() {
        maybe_clear_graphic_before_write();
        if let Some(mut g) = cons.try_lock() {
            let _ = g.write_fmt(fmt);
        }
    }
}

/// Writes a string slice into the serial, and the graphic console if it exists.
pub fn console_write_str(s: &str) {
    serial_write_str(s);
    graphic_console_write_str(s);
}

/// Writes formatted data into the serial, and the graphic console if it exists.
pub fn console_write_fmt(fmt: Arguments) {
    serial_write_fmt(fmt);
    graphic_console_write_fmt(fmt);
}

/// Read buffer data from console (serial).
pub async fn console_read(buf: &mut [u8]) -> usize {
    super::future::SerialReadFuture::new(buf).await
}

/// The POSIX `winsize` structure.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ConsoleWinSize {
    pub ws_row: u16,
    pub ws_col: u16,
    pub ws_xpixel: u16,
    pub ws_ypixel: u16,
}

/// Returns the size information of the console, see [`ConsoleWinSize`].
pub fn console_win_size() -> ConsoleWinSize {
    #[cfg(feature = "graphic")]
    if let Some(&winsz) = CONSOLE_WIN_SIZE.try_get() {
        return winsz;
    }
    ConsoleWinSize::default()
}

#[macro_export]
macro_rules! klog_info {
    ($($arg:tt)*) => {
        $crate::console::klog_emit(
            $crate::console::LOG_INFO,
            &::alloc::format!($($arg)*),
        )
    };
}

#[macro_export]
macro_rules! klog_warn {
    ($($arg:tt)*) => {
        $crate::console::klog_emit(
            $crate::console::LOG_WARNING,
            &::alloc::format!($($arg)*),
        )
    };
}

#[macro_export]
macro_rules! klog_err {
    ($($arg:tt)*) => {
        $crate::console::klog_emit(
            $crate::console::LOG_ERR,
            &::alloc::format!($($arg)*),
        )
    };
}
