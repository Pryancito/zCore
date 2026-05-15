use core::fmt::{self, Write};
use log::{self, Level, LevelFilter, Log, Metadata, Record};

// ---------------------------------------------------------------------------
// Kernel log ring buffer  (exposed as "dmesg")
// ---------------------------------------------------------------------------
//
// A fixed 256 KiB circular buffer holds all kernel log messages.
// Access is serialized with a simple spinlock so it is safe to call from
// any context, including interrupt handlers.

const KLOG_BUF_SIZE: usize = 256 * 1024; // 256 KiB

struct KlogBuf {
    buf:   [u8; KLOG_BUF_SIZE],
    head:  usize,   // write pointer (wraps around)
    used:  usize,   // bytes currently stored (≤ KLOG_BUF_SIZE)
}

impl KlogBuf {
    const fn new() -> Self {
        Self { buf: [0u8; KLOG_BUF_SIZE], head: 0, used: 0 }
    }

    /// Append bytes; oldest data is silently overwritten when full.
    fn write(&mut self, data: &[u8]) {
        for &b in data {
            self.buf[self.head] = b;
            self.head = (self.head + 1) % KLOG_BUF_SIZE;
            if self.used < KLOG_BUF_SIZE {
                self.used += 1;
            }
        }
    }

    /// Copy the stored bytes (oldest first) into `dst`.
    /// Returns the number of bytes written.
    fn read_all(&self, dst: &mut [u8]) -> usize {
        let len = self.used.min(dst.len());
        if len == 0 { return 0; }
        // start = position of oldest byte
        let start = if self.used < KLOG_BUF_SIZE {
            0
        } else {
            self.head  // head points to the oldest byte when full
        };
        for i in 0..len {
            dst[i] = self.buf[(start + i) % KLOG_BUF_SIZE];
        }
        len
    }

    fn size(&self) -> usize { self.used }
}

struct KlogLock {
    locked: core::sync::atomic::AtomicBool,
    buf:    core::cell::UnsafeCell<KlogBuf>,
}

// SAFETY: we serialise all access with the spinlock.
unsafe impl Sync for KlogLock {}
unsafe impl Send for KlogLock {}

impl KlogLock {
    const fn new() -> Self {
        Self {
            locked: core::sync::atomic::AtomicBool::new(false),
            buf: core::cell::UnsafeCell::new(KlogBuf::new()),
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut KlogBuf) -> R) -> R {
        use core::sync::atomic::Ordering;
        // Spin until we acquire the lock.
        while self.locked.compare_exchange_weak(
            false, true, Ordering::Acquire, Ordering::Relaxed
        ).is_err() {
            core::hint::spin_loop();
        }
        // SAFETY: we hold the lock.
        let r = f(unsafe { &mut *self.buf.get() });
        self.locked.store(false, Ordering::Release);
        r
    }
}

static KLOG: KlogLock = KlogLock::new();

/// Write a slice of bytes into the kernel log ring buffer.
fn klog_write(data: &[u8]) {
    KLOG.with(|b| b.write(data));
}

/// Copy the full kernel log into `dst` (oldest first).
/// Returns the number of bytes written.
pub fn klog_read_all(dst: &mut [u8]) -> usize {
    KLOG.with(|b| b.read_all(dst))
}

/// Total bytes currently stored in the kernel log ring buffer.
pub fn klog_size() -> usize {
    KLOG.with(|b| b.size())
}

/// Write a kernel message into the dmesg ring buffer only (not echoed to the graphic/serial console).
/// `priority` follows syslog(3): 3=err, 4=warn, 6=info, 7=debug.
pub fn klog_emit(priority: u8, msg: &str) {
    let now = kernel_hal::timer::timer_now();
    let micros = now.as_micros();
    let mut line = [0u8; 512];
    struct W<'a> { buf: &'a mut [u8], pos: usize }
    impl fmt::Write for W<'_> {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            let n = s.len().min(self.buf.len().saturating_sub(self.pos));
            self.buf[self.pos..self.pos + n].copy_from_slice(&s.as_bytes()[..n]);
            self.pos += n;
            Ok(())
        }
    }
    let pos = {
        let mut w = W { buf: &mut line, pos: 0 };
        let _ = write!(
            w,
            "<{prio}>[{s:>3}.{us:06}] {msg}\n",
            prio = priority,
            s = micros / 1_000_000,
            us = micros % 1_000_000,
            msg = msg.trim_end_matches('\n'),
        );
        w.pos
    };
    klog_write(&line[..pos]);
}

/// Initialize logging with the default max log level (WARN).
pub fn init() {
    static LOGGER: SimpleLogger = SimpleLogger;
    log::set_logger(&LOGGER).unwrap();
    log::set_max_level(LevelFilter::Warn);
    // Register the ring-buffer accessors so linux-syscall can read them.
    kernel_hal::console::klog_register(klog_read_all, klog_size, klog_emit);
}

/// Reset max log level.
pub fn set_max_level(level: &str) {
    log::set_max_level(level.parse().unwrap_or(LevelFilter::Warn));
}

#[macro_export]
macro_rules! klog_info {
    ($($arg:tt)*) => {
        $crate::logging::klog_emit(6, &::alloc::format!($($arg)*))
    };
}

#[macro_export]
macro_rules! klog_warn {
    ($($arg:tt)*) => {
        $crate::logging::klog_emit(4, &::alloc::format!($($arg)*))
    };
}

#[macro_export]
macro_rules! klog_err {
    ($($arg:tt)*) => {
        $crate::logging::klog_emit(3, &::alloc::format!($($arg)*))
    };
}

#[inline]
pub fn print(args: fmt::Arguments) {
    kernel_hal::console::console_write_fmt(args);
}

#[allow(dead_code)]
#[inline]
pub fn debug_print(args: fmt::Arguments) {
    kernel_hal::console::debug_write_fmt(args);
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::logging::print(core::format_args!($($arg)*));
    }
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\r\n"));
    ($($arg:tt)*) => {
        $crate::logging::print(core::format_args!($($arg)*));
        $crate::print!("\r\n");
    }
}

#[macro_export]
macro_rules! debug_print {
    ($($arg:tt)*) => {
        $crate::logging::debug_print(core::format_args!($($arg)*));
    }
}

#[macro_export]
macro_rules! debug_println {
    () => ($crate::print!("\r\n"));
    ($($arg:tt)*) => {
        $crate::logging::debug_print(core::format_args!($($arg)*));
        $crate::debug_print!("\r\n");
    }
}

#[allow(dead_code)]
#[repr(u8)]
enum ColorCode {
    Black = 30,
    Red = 31,
    Green = 32,
    Yellow = 33,
    Blue = 34,
    Magenta = 35,
    Cyan = 36,
    White = 37,
    BrightBlack = 90,
    BrightRed = 91,
    BrightGreen = 92,
    BrightYellow = 93,
    BrightBlue = 94,
    BrightMagenta = 95,
    BrightCyan = 96,
    BrightWhite = 97,
}

/// Add escape sequence to print with color in Linux console
macro_rules! with_color {
    ($color_code:expr, $($arg:tt)*) => {{
        #[cfg(feature = "colorless-log")]
        { let _ = $color_code; format_args!($($arg)*) }
        #[cfg(not(feature = "colorless-log"))]
        { format_args!("\u{1B}[{}m{}\u{1B}[m", $color_code as u8, format_args!($($arg)*)) }
    }};
}

struct SimpleLogger;

impl Log for SimpleLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let now = kernel_hal::timer::timer_now();
        let cpu_id = kernel_hal::cpu::cpu_id();
        let (tid, pid) = (0, 0); //kernel_hal::thread::get_tid();
        let level = record.level();
        let target = record.target();
        let level_color = match level {
            Level::Error => ColorCode::BrightRed,
            Level::Warn => ColorCode::BrightYellow,
            Level::Info => ColorCode::BrightGreen,
            Level::Debug => ColorCode::BrightCyan,
            Level::Trace => ColorCode::BrightBlack,
        };
        let args_color = match level {
            Level::Error => ColorCode::Red,
            Level::Warn => ColorCode::Yellow,
            Level::Info => ColorCode::Green,
            Level::Debug => ColorCode::Cyan,
            Level::Trace => ColorCode::BrightBlack,
        };
        // Primary log output: serial + (later) native graphic console.
        print(with_color!(
            ColorCode::White,
            "[{time} {level} {info} {data}\n",
            time = {
                cfg_if! {
                    if #[cfg(feature = "libos")] {
                        use chrono::{TimeZone, Local};
                        Local.timestamp_nanos(now.as_nanos() as _).format("%Y-%m-%d %H:%M:%S%.6f")
                    } else {
                        let micros = now.as_micros();
                        format_args!("{s:>3}.{us:06}", s = micros / 1_000_000, us = micros % 1_000_000)
                    }
                }
            },
            level = with_color!(level_color, "{level:<5}"),
            info = with_color!(ColorCode::White, "{cpu_id} {pid}:{tid} {target}]"),
            data = with_color!(args_color, "{args}", args = record.args()),
        ));

        // Also write a plain-text copy into the ring buffer for dmesg.
        {
            struct KlogWriter { buf: [u8; 1024], pos: usize }
            impl fmt::Write for KlogWriter {
                fn write_str(&mut self, s: &str) -> fmt::Result {
                    let bytes = s.as_bytes();
                    let free = self.buf.len().saturating_sub(self.pos);
                    let n = bytes.len().min(free);
                    self.buf[self.pos..self.pos + n].copy_from_slice(&bytes[..n]);
                    self.pos += n;
                    Ok(())
                }
            }
            let mut w = KlogWriter { buf: [0u8; 1024], pos: 0 };
            let micros = now.as_micros();
            let syslog_prio = match level {
                Level::Error => 3u8,
                Level::Warn  => 4,
                Level::Info  => 6,
                Level::Debug => 7,
                Level::Trace => 7,
            };
            let _ = core::fmt::write(
                &mut w,
                format_args!(
                    "<{prio}>[{s:>3}.{us:06}] {args}\n",
                    prio = syslog_prio,
                    s  = micros / 1_000_000,
                    us = micros % 1_000_000,
                    args = record.args(),
                ),
            );
            klog_write(&w.buf[..w.pos]);
        }

        // When running with `LOG=debug` (or more verbose) we still don't have a native GPU
        // driver early in boot. Mirror logs to the UEFI GOP framebuffer console so we can
        // see early boot progress on real hardware.
        //
        // IMPORTANT: The early framebuffer console can't interpret ANSI escapes, so
        // keep this output plain (no colors).
        #[cfg(feature = "graphic")]
        if log::max_level() >= LevelFilter::Debug {
            cfg_if! {
                if #[cfg(feature = "libos")] {
                    use chrono::{TimeZone, Local};
                    kernel_hal::console::debug_write_fmt(format_args!(
                        "[{time} {level:<5} {cpu_id} {pid}:{tid} {target}] {args}\n",
                        time = Local.timestamp_nanos(now.as_nanos() as _).format("%Y-%m-%d %H:%M:%S%.6f"),
                        level = level,
                        cpu_id = cpu_id,
                        pid = pid,
                        tid = tid,
                        target = target,
                        args = record.args(),
                    ));
                } else {
                    let micros = now.as_micros();
                    let s = micros / 1_000_000;
                    let us = micros % 1_000_000;
                    kernel_hal::console::debug_write_fmt(format_args!(
                        "[{s:>3}.{us:06} {level:<5} {cpu_id} {pid}:{tid} {target}] {args}\n",
                        s = s,
                        us = us,
                        level = level,
                        cpu_id = cpu_id,
                        pid = pid,
                        tid = tid,
                        target = target,
                        args = record.args(),
                    ));
                }
            }
        }
    }

    fn flush(&self) {}
}
