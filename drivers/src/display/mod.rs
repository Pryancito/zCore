//! Only UEFI Display currently.

mod nvidia;
mod uefi;

pub use nvidia::{set_boot_fb_info, NvidiaGpu, NvidiaGpuDriverPci};
pub use uefi::UefiDisplay;
