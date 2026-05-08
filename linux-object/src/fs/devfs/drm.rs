//! DRM (Direct Rendering Manager) Subsystem for zCore
//!
//! Provides a unified interface for graphics drivers (NVIDIA, VirtIO, etc.)
//! and handles buffer management (GEM) and mode setting (KMS).

use alloc::sync::Arc;
use alloc::vec::Vec;
use lock::Mutex;

pub use zcore_drivers::scheme::drm::{DrmCaps, DrmConnector, DrmCrtc, DrmPlane, GemHandle};
use zcore_drivers::scheme::DrmScheme;
use zircon_object::vm::{pages, MMUFlags, VmObject};

/// A DRM Framebuffer object
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct DrmFramebuffer {
    pub id: u32,
    /// GEM handle that backs this framebuffer
    pub gem_handle_id: u32,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub phys_addr: u64,
    pub size: usize,
}

struct DrmState {
    drivers: Vec<Arc<dyn DrmScheme>>,
    next_handle_id: u32,
    next_fb_id: u32,
    handles: Vec<(GemHandle, Arc<VmObject>)>,
    framebuffers: Vec<DrmFramebuffer>,
}

lazy_static::lazy_static! {
    static ref DRM_STATE: Mutex<DrmState> = Mutex::new(DrmState {
        drivers: Vec::new(),
        next_handle_id: 1,
        next_fb_id: 1,
        handles: Vec::new(),
        framebuffers: Vec::new(),
    });
}

/// Register a new DRM driver
pub fn register_driver(driver: Arc<dyn DrmScheme>) {
    let mut state = DRM_STATE.lock();
    if driver.name() == "simplefb" {
        state.drivers.push(driver);
    } else {
        state.drivers.insert(0, driver);
    }
}

/// Get the primary DRM driver
pub fn get_primary_driver() -> Option<Arc<dyn DrmScheme>> {
    DRM_STATE.lock().drivers.first().cloned()
}

/// Allocate a buffer (GEM object) via the primary driver
pub fn alloc_buffer(size: usize) -> Option<GemHandle> {
    if size == 0 {
        return None;
    }
    let mut state = DRM_STATE.lock();
    let driver = state.drivers.first()?.clone();
    let id = state.next_handle_id;
    state.next_handle_id += 1;

    // Allocate contiguous physical memory via VMO
    let vmo = VmObject::new_contiguous(pages(size), 12).ok()?;
    let phys_addr = vmo.commit_page(0, MMUFlags::READ).ok()? as u64;

    let handle = GemHandle {
        id,
        size,
        phys_addr,
    };

    // Tell the driver about the new buffer
    if driver.import_buffer(handle) {
        state.handles.push((handle, vmo));
        return Some(handle);
    }
    None
}

pub fn get_handle(handle_id: u32) -> Option<GemHandle> {
    DRM_STATE
        .lock()
        .handles
        .iter()
        .find(|(h, _)| h.id == handle_id)
        .map(|(h, _)| *h)
}

/// Create a framebuffer from a GEM handle
pub fn create_fb(handle_id: u32, width: u32, height: u32, pitch: u32) -> Option<u32> {
    let handle = get_handle(handle_id)?;
    let driver = get_primary_driver()?;

    let _hardware_fb_id = driver.create_fb(handle_id, width, height, pitch)?;

    let mut state = DRM_STATE.lock();
    let fb_id = state.next_fb_id;
    state.next_fb_id += 1;

    let fb = DrmFramebuffer {
        id: fb_id,
        gem_handle_id: handle_id,
        width,
        height,
        pitch,
        phys_addr: handle.phys_addr,
        size: (pitch as usize) * (height as usize),
    };

    state.framebuffers.push(fb);
    Some(fb_id)
}

pub fn page_flip(fb_id: u32) -> bool {
    if let Some(driver) = get_primary_driver() {
        driver.page_flip(fb_id)
    } else {
        false
    }
}

pub fn get_caps() -> Option<DrmCaps> {
    get_primary_driver().map(|d| d.get_caps())
}

pub fn gem_close(handle_id: u32) -> bool {
    let mut state = DRM_STATE.lock();
    if let Some(pos) = state.handles.iter().position(|(h, _)| h.id == handle_id) {
        let (handle, _) = state.handles[pos];
        let driver = state.drivers.first().cloned();
        state.handles.remove(pos);
        drop(state);

        if let Some(d) = driver {
            d.free_buffer(handle);
        }
        true
    } else {
        false
    }
}

pub fn get_resources() -> (Vec<u32>, Vec<u32>, Vec<u32>) {
    let state = DRM_STATE.lock();
    let fbs: Vec<u32> = state.framebuffers.iter().map(|fb| fb.id).collect();
    let mut crtcs = Vec::new();
    let mut connectors = Vec::new();

    for driver in &state.drivers {
        let (_, d_crtcs, d_conns) = driver.get_resources();
        crtcs.extend(d_crtcs);
        connectors.extend(d_conns);
    }

    (fbs, crtcs, connectors)
}

pub fn get_connector(id: u32) -> Option<DrmConnector> {
    let state = DRM_STATE.lock();
    for driver in &state.drivers {
        if let Some(conn) = driver.get_connector(id) {
            return Some(conn);
        }
    }
    None
}

pub fn get_crtc(id: u32) -> Option<DrmCrtc> {
    let state = DRM_STATE.lock();
    for driver in &state.drivers {
        if let Some(crtc) = driver.get_crtc(id) {
            return Some(crtc);
        }
    }
    None
}

pub fn get_planes() -> Vec<u32> {
    let state = DRM_STATE.lock();
    let mut planes = Vec::new();
    for driver in &state.drivers {
        planes.extend(driver.get_planes());
    }
    planes
}

pub fn get_plane(id: u32) -> Option<DrmPlane> {
    let state = DRM_STATE.lock();
    for driver in &state.drivers {
        if let Some(plane) = driver.get_plane(id) {
            return Some(plane);
        }
    }
    None
}
