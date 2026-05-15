//! AHCI (Advanced Host Controller Interface) Driver for Eclipse OS 2
//!
//! Adapted from the previous Eclipse OS AHCI driver to work with the new
//! zCore-based driver architecture.

use alloc::format;
use alloc::string::String;
use core::hint::spin_loop;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, Ordering};

use crate::bus::{drivers_dma_alloc, drivers_timer_now_as_micros, phys_to_virt, virt_to_phys};
use crate::scheme::{BlockScheme, Scheme};
use crate::{Device, DeviceError, DeviceResult};
use crate::bus::pci_drivers::PciDriver;
use crate::builder::IoMapper;
use alloc::sync::Arc;
use pci::{PCIDevice, BAR};

use lock::Mutex;

// --- HBA global register offsets ---
const HBA_GHC: usize = 0x04;
const HBA_PI: usize = 0x0C;

const GHC_AE: u32 = 1 << 31;
const GHC_HR: u32 = 1 << 0;

// --- Per-port register offsets ---
const PORT_CLB: usize = 0x00;
const PORT_CLBU: usize = 0x04;
const PORT_FB: usize = 0x08;
const PORT_FBU: usize = 0x0C;
const PORT_IS: usize = 0x10;
const PORT_IE: usize = 0x14;
const PORT_CMD: usize = 0x18;
const PORT_TFD: usize = 0x20;
const PORT_SIG: usize = 0x24;
const PORT_SSTS: usize = 0x28;
const PORT_SCTL: usize = 0x2C;
const PORT_SERR: usize = 0x30;
const PORT_CI: usize = 0x38;

const CMD_ST: u32 = 1 << 0;
const CMD_SUD: u32 = 1 << 1;
const CMD_POD: u32 = 1 << 2;
const CMD_FRE: u32 = 1 << 4;
const CMD_FR: u32 = 1 << 14;
const CMD_CR: u32 = 1 << 15;

const ATA_DEV_BUSY: u8 = 0x80;
const ATA_DEV_DRQ: u8 = 0x08;

const HBA_SIG_ATA: u32 = 0x0000_0101;
const FIS_TYPE_REG_H2D: u8 = 0x27;

const ATA_CMD_READ_DMA_EXT: u8 = 0x25;
const ATA_CMD_WRITE_DMA_EXT: u8 = 0x35;
const ATA_CMD_IDENTIFY: u8 = 0xEC;

const SECTOR_SIZE: usize = 512;

// AHCI spec §4.2.2: each Command Header is 32 bytes; the Command List base
// address must be 1 KiB-aligned (provided by drivers_dma_alloc → 4 KiB page).
#[repr(C)]
struct CommandHeader {
    cfl: u8,
    pm: u8,
    prdtl: u16,
    prdbc: u32,
    ctba: u32,
    ctbau: u32,
    reserved: [u32; 4],
}

#[repr(C)]
struct PrdEntry {
    dba: u32,
    dbau: u32,
    _rsvd: u32,
    dbc_ioc: u32,
}

#[repr(C, align(128))]
struct CommandTable {
    cfis: [u8; 64],
    acmd: [u8; 16],
    _rsvd: [u8; 48],
    prdt: [PrdEntry; 1],
}

const CMD_SLOTS: usize = 32;
const CMD_TABLE_STRIDE: usize = 256; // 128-aligned, fits CommandTable

// DMA memory layout (3 pages = 12 288 bytes):
//   [0..1024)      command list  : CMD_SLOTS × sizeof(CommandHeader) = 32 × 32 = 1024 B
//   [1024..1280)   FIS recv area : 256 B  (256-byte aligned ✓)
//   [4096..12288)  command tables: CMD_SLOTS × CMD_TABLE_STRIDE = 32 × 256 = 8192 B
const DMA_PAGES: usize = 3;

// AHCI spec §10.4.2: COMRESET must be asserted for at least 1 ms.
const COMRESET_US: u64 = 1_000;
// AHCI spec §10.4.2: device reinitialization after COMRESET must complete within
// 10 seconds; we give it 1 second.
const PHY_LINK_TIMEOUT_US: u64 = 1_000_000;
// Timeout for HBA global reset to self-clear (spec: 1 second).
const HBA_RESET_TIMEOUT_US: u64 = 1_000_000;
// Timeout for stop_engine: CR and FR must clear within 500 ms (AHCI spec).
const ENGINE_STOP_TIMEOUT_US: u64 = 500_000;
// Timeout for exec_cmd: 10 seconds covers slow spinning disks.
const CMD_TIMEOUT_US: u64 = 10_000_000;
// Shorter timeout for ATA IDENTIFY during init — 5 seconds is enough.
const IDENTIFY_TIMEOUT_US: u64 = 5_000_000;
// Timeout for port TFD-busy before issuing a command: 2 seconds.
const TFD_TIMEOUT_US: u64 = 2_000_000;

/// Busy-wait for `us` microseconds using the TSC-based driver timer.
#[inline]
fn udelay(us: u64) {
    let t0 = unsafe { drivers_timer_now_as_micros() };
    // Hard spin guard: prevents infinite loop if TSC-based timer does not advance
    // (e.g. cpu_frequency() returned a wrong value, or early-boot timer quirk).
    // At ~1 GHz effective spin rate, 10 M iterations ≈ 10 ms; at 4 GHz ≈ 2.5 ms.
    // This fires only when the timer is genuinely broken; normally the timer-based
    // condition exits first.
    const MAX_SPINS: u64 = 10_000_000;
    let mut spins = 0u64;
    while unsafe { drivers_timer_now_as_micros() }.wrapping_sub(t0) < us {
        spin_loop();
        spins = spins.wrapping_add(1);
        if spins >= MAX_SPINS {
            warn!("[AHCI] udelay fallback hit ({}us requested — timer did not advance)", us);
            break;
        }
    }
}

/// Busy-wait until `pred()` returns true or `timeout_us` elapses.
/// Returns true if the condition was met, false on timeout.
/// Includes a hard spin-count cap so the function always terminates even
/// if `drivers_timer_now_as_micros()` returns a constant (broken timer).
#[inline]
fn wait_until<F: Fn() -> bool>(timeout_us: u64, pred: F) -> bool {
    let t0 = unsafe { drivers_timer_now_as_micros() };
    // Maximum iterations: 500 M is ~500 ms at 1 GHz, ~125 ms at 4 GHz.
    // We scale by the requested timeout to keep proportional coverage.
    // At worst this adds a 500 ms hard cap per call, which is acceptable
    // for a boot path but ensures we never hang the system indefinitely.
    let max_spins: u64 = 500_000_000u64.max(timeout_us.saturating_mul(500));
    let mut spins = 0u64;
    loop {
        if pred() { return true; }
        spin_loop();
        spins = spins.wrapping_add(1);
        if unsafe { drivers_timer_now_as_micros() }.wrapping_sub(t0) >= timeout_us {
            return false;
        }
        if spins >= max_spins {
            warn!("[AHCI] wait_until fallback: timer stuck, forcing timeout after {} spins", spins);
            return false;
        }
    }
}

struct AhciPort {
    base: usize,
    port_idx: u32,
    cl_phys: u64,
    cl_virt: usize,
    fb_phys: u64,
    _fb_virt: usize,
    ct_phys: u64,
    ct_virt: usize,
}

impl AhciPort {
    fn read_reg(&self, offset: usize) -> u32 {
        unsafe { read_volatile((self.base + offset) as *const u32) }
    }

    fn write_reg(&self, offset: usize, val: u32) {
        unsafe { write_volatile((self.base + offset) as *mut u32, val) }
    }

    fn stop_engine(&self) {
        self.write_reg(PORT_CMD, self.read_reg(PORT_CMD) & !CMD_ST);
        self.write_reg(PORT_CMD, self.read_reg(PORT_CMD) & !CMD_FRE);
        // AHCI spec requires CR and FR to clear within 500 ms of clearing ST/FRE.
        if !wait_until(ENGINE_STOP_TIMEOUT_US, || {
            self.read_reg(PORT_CMD) & (CMD_CR | CMD_FR) == 0
        }) {
            warn!(
                "[AHCI] Port {} stop_engine timeout (CR/FR stuck)",
                self.port_idx
            );
        }
    }

    fn start_engine(&self) {
        // AHCI spec: wait for CR to clear before setting FRE and ST.
        if !wait_until(ENGINE_STOP_TIMEOUT_US, || {
            self.read_reg(PORT_CMD) & CMD_CR == 0
        }) {
            warn!(
                "[AHCI] Port {} start_engine timeout (CR stuck)",
                self.port_idx
            );
        }
        self.write_reg(PORT_CMD, self.read_reg(PORT_CMD) | CMD_FRE | CMD_ST);
    }

    fn init(&self) {
        self.stop_engine();

        // Configure command list
        unsafe {
            let headers = self.cl_virt as *mut CommandHeader;
            for i in 0..CMD_SLOTS {
                let h = &mut *headers.add(i);
                let ct_phys = self.ct_phys + (i * CMD_TABLE_STRIDE) as u64;
                h.ctba = ct_phys as u32;
                h.ctbau = (ct_phys >> 32) as u32;
                h.prdtl = 0;
                h.cfl = 0;
            }
        }

        self.write_reg(PORT_CLB, self.cl_phys as u32);
        self.write_reg(PORT_CLBU, (self.cl_phys >> 32) as u32);
        self.write_reg(PORT_FB, self.fb_phys as u32);
        self.write_reg(PORT_FBU, (self.fb_phys >> 32) as u32);

        self.write_reg(PORT_IS, 0xFFFF_FFFF);
        self.write_reg(PORT_SERR, 0xFFFF_FFFF);
        self.write_reg(PORT_IE, 0);

        self.write_reg(
            PORT_CMD,
            self.read_reg(PORT_CMD) | CMD_POD | CMD_SUD | CMD_FRE,
        );

        // COMRESET: assert DET=1 for at least 1 ms, then release
        self.write_reg(PORT_SCTL, (self.read_reg(PORT_SCTL) & !0xF) | 1);
        udelay(COMRESET_US);
        self.write_reg(PORT_SCTL, self.read_reg(PORT_SCTL) & !0xF);

        // Wait for PHY to establish link (DET=3), max 1 second
        if !wait_until(PHY_LINK_TIMEOUT_US, || self.read_reg(PORT_SSTS) & 0xF == 3) {
            crate::klog_warn!("[AHCI] port {} PHY link timeout", self.port_idx);
        }

        self.write_reg(PORT_SERR, 0xFFFF_FFFF);
        self.start_engine();
    }

    fn reset_port(&self) {
        self.stop_engine();
        // COMRESET: set DET=1, wait ≥1 ms (AHCI spec §10.4.2), then clear DET
        self.write_reg(PORT_SCTL, (self.read_reg(PORT_SCTL) & !0xF) | 1);
        udelay(COMRESET_US);
        self.write_reg(PORT_SCTL, self.read_reg(PORT_SCTL) & !0xF);
        // Wait for PHY to re-establish link (DET=3), max 1 second
        if !wait_until(PHY_LINK_TIMEOUT_US, || self.read_reg(PORT_SSTS) & 0xF == 3) {
            warn!("[AHCI] Port {} reset_port: PHY link timeout", self.port_idx);
        }
        self.write_reg(PORT_SERR, 0xFFFF_FFFF);
        self.write_reg(PORT_IS, 0xFFFF_FFFF);
        self.start_engine();
    }

    fn exec_cmd(&self, slot: u32) -> DeviceResult {
        self.exec_cmd_with_timeout(slot, CMD_TIMEOUT_US)
    }

    fn exec_cmd_with_timeout(&self, slot: u32, timeout_us: u64) -> DeviceResult {
        fence(Ordering::SeqCst);
        self.write_reg(PORT_IS, 0xFFFF_FFFF);
        self.write_reg(PORT_CI, 1 << slot);

        if !wait_until(timeout_us, || self.read_reg(PORT_CI) & (1 << slot) == 0) {
            crate::klog_err!(
                "[AHCI] port {} command timeout ({} ms)",
                self.port_idx,
                timeout_us / 1000
            );
            self.reset_port();
            return Err(DeviceError::IoError);
        }

        if self.read_reg(PORT_IS) & (1 << 30) != 0 {
            crate::klog_err!("[AHCI] port {} task file error", self.port_idx);
            self.reset_port();
            return Err(DeviceError::IoError);
        }

        Ok(())
    }

    fn rw_block(&self, lba: u64, buf_phys: u64, buf_len: usize, write: bool) -> DeviceResult {
        let slot = 0u32;

        // Wait for port to become ready (TFD BUSY/DRQ clear), max 2 seconds
        if !wait_until(TFD_TIMEOUT_US, || {
            self.read_reg(PORT_TFD) & ((ATA_DEV_BUSY | ATA_DEV_DRQ) as u32) == 0
        }) {
            crate::klog_err!(
                "[AHCI] port {} TFD busy timeout before command",
                self.port_idx
            );
            self.reset_port();
            return Err(DeviceError::IoError);
        }

        unsafe {
            let cmd_table = self.ct_virt as *mut CommandTable;
            core::ptr::write_bytes(
                cmd_table as *mut u8,
                0,
                core::mem::size_of::<CommandTable>(),
            );

            let fis = (*cmd_table).cfis.as_mut_ptr();
            *fis.add(0) = FIS_TYPE_REG_H2D;
            *fis.add(1) = 0x80;
            *fis.add(2) = if write {
                ATA_CMD_WRITE_DMA_EXT
            } else {
                ATA_CMD_READ_DMA_EXT
            };
            *fis.add(4) = lba as u8;
            *fis.add(5) = (lba >> 8) as u8;
            *fis.add(6) = (lba >> 16) as u8;
            *fis.add(7) = 1 << 6;
            *fis.add(8) = (lba >> 24) as u8;
            *fis.add(9) = (lba >> 32) as u8;
            *fis.add(10) = (lba >> 40) as u8;
            let count = (buf_len / SECTOR_SIZE) as u16;
            *fis.add(12) = count as u8;
            *fis.add(13) = (count >> 8) as u8;

            (*cmd_table).prdt[0].dba = buf_phys as u32;
            (*cmd_table).prdt[0].dbau = (buf_phys >> 32) as u32;
            (*cmd_table).prdt[0].dbc_ioc = ((buf_len as u32) - 1) | (1 << 31);

            let header = self.cl_virt as *mut CommandHeader;
            (*header).cfl = 5 | (if write { 1 << 6 } else { 0 });
            (*header).prdtl = 1;
            (*header).prdbc = 0;
        }

        self.exec_cmd(slot)
    }

    fn identify(&self) -> Option<u64> {
        let slot = 0u32;
        let paddr = unsafe { drivers_dma_alloc(1) };
        let vaddr = phys_to_virt(paddr);

        unsafe {
            let cmd_table = self.ct_virt as *mut CommandTable;
            core::ptr::write_bytes(
                cmd_table as *mut u8,
                0,
                core::mem::size_of::<CommandTable>(),
            );

            let fis = (*cmd_table).cfis.as_mut_ptr();
            *fis.add(0) = FIS_TYPE_REG_H2D;
            *fis.add(1) = 0x80;
            *fis.add(2) = ATA_CMD_IDENTIFY;

            (*cmd_table).prdt[0].dba = paddr as u32;
            (*cmd_table).prdt[0].dbau = (paddr >> 32) as u32;
            (*cmd_table).prdt[0].dbc_ioc = 511 | (1 << 31);

            let header = self.cl_virt as *mut CommandHeader;
            (*header).cfl = 5;
            (*header).prdtl = 1;
            (*header).prdbc = 0;
        }

        if self.exec_cmd_with_timeout(slot, IDENTIFY_TIMEOUT_US).is_err() {
            return None;
        }

        let id = unsafe { core::slice::from_raw_parts(vaddr as *const u16, 256) };
        let lba48 = (id[100] as u64)
            | ((id[101] as u64) << 16)
            | ((id[102] as u64) << 32)
            | ((id[103] as u64) << 48);
        let lba28 = (id[60] as u64) | ((id[61] as u64) << 16);
        let sectors = if lba48 != 0 { lba48 } else { lba28 };

        Some(sectors)
    }
}

pub struct AhciInterface {
    name: String,
    port: Mutex<AhciPort>,
    _capacity: u64,
}

impl AhciInterface {
    pub fn new(base: usize, _irq: usize) -> DeviceResult<Self> {
        unsafe {
            write_volatile((base + HBA_GHC) as *mut u32, GHC_AE);
            write_volatile((base + HBA_GHC) as *mut u32, GHC_AE | GHC_HR);
            // Wait for HBA Global Reset to self-clear (spec: ≤1 second)
            if !wait_until(HBA_RESET_TIMEOUT_US, || {
                read_volatile((base + HBA_GHC) as *const u32) & GHC_HR == 0
            }) {
                crate::klog_err!("[AHCI] HBA reset timeout — controller may not be functional");
            }
            write_volatile((base + HBA_GHC) as *mut u32, GHC_AE);
            // AHCI spec §10.1.2: minimum 1 ms after GHC.HR before touching registers.
            udelay(1_000);
        }

        let pi = unsafe { read_volatile((base + HBA_PI) as *const u32) };

        for i in 0..32 {
            if pi & (1 << i) != 0 {
                let pbase = base + 0x100 + (i * 0x80);
                let dma_paddr = unsafe { drivers_dma_alloc(DMA_PAGES) };
                let dma_vaddr = phys_to_virt(dma_paddr);

                let port = AhciPort {
                    base: pbase,
                    port_idx: i as u32,
                    cl_phys: dma_paddr as u64,
                    cl_virt: dma_vaddr,
                    fb_phys: (dma_paddr + 1024) as u64,
                    _fb_virt: dma_vaddr + 1024,
                    ct_phys: (dma_paddr + 4096) as u64,
                    ct_virt: dma_vaddr + 4096,
                };

                // Skip COMRESET/link waits on ports with no device (DET=0).
                if port.read_reg(PORT_SSTS) & 0xF == 0 {
                    continue;
                }

                port.init();

                // Wait up to 1 second for PORT_SIG to become valid
                // (10ms × 100 = 1 s). Use TSC-based udelay to avoid
                // non-deterministic spin counts on different CPUs.
                let mut sig = 0;
                for _ in 0..100 {
                    sig = port.read_reg(PORT_SIG);
                    if sig != 0 && sig != 0xFFFF_FFFF {
                        break;
                    }
                    udelay(10_000); // 10 ms between polls
                }

                if sig == HBA_SIG_ATA {
                    if let Some(sectors) = port.identify() {
                        crate::klog_info!(
                            "ahci{}: SATA disk attached, {} sectors ({} MiB)",
                            i,
                            sectors,
                            sectors / 2048
                        );
                        return Ok(Self {
                            name: format!("ahci-{}", i),
                            port: Mutex::new(port),
                            _capacity: sectors,
                        });
                    }
                }
            }
        }

        Err(DeviceError::NoResources)
    }
}

impl BlockScheme for AhciInterface {
    fn read_block(&self, block_id: usize, read_buf: &mut [u8]) -> DeviceResult {
        let lba = (block_id * (read_buf.len() / SECTOR_SIZE)) as u64;
        let paddr = virt_to_phys(read_buf.as_ptr() as usize);
        self.port
            .lock()
            .rw_block(lba, paddr as u64, read_buf.len(), false)
    }

    fn write_block(&self, block_id: usize, write_buf: &[u8]) -> DeviceResult {
        let lba = (block_id * (write_buf.len() / SECTOR_SIZE)) as u64;
        let paddr = virt_to_phys(write_buf.as_ptr() as usize);
        self.port
            .lock()
            .rw_block(lba, paddr as u64, write_buf.len(), true)
    }

    fn flush(&self) -> DeviceResult {
        Ok(())
    }
}

impl Scheme for AhciInterface {
    fn name(&self) -> &str {
        &self.name
    }

    fn handle_irq(&self, _irq: usize) {}
}

pub struct AhciDriverPci;

impl PciDriver for AhciDriverPci {
    fn name(&self) -> &str {
        "ahci"
    }

    fn matched(&self, _vendor_id: u16, _device_id: u16) -> bool {
        false
    }

    fn matched_dev(&self, dev: &PCIDevice) -> bool {
        // Match standard AHCI: class=0x01 (mass storage), subclass=0x06 (SATA), prog_if=0x01 (AHCI)
        dev.id.class == 0x01 && dev.id.subclass == 0x06 && dev.id.prog_if == 0x01
    }

    fn init(&self, dev: &PCIDevice, mapper: &Option<Arc<dyn IoMapper>>, irq: Option<usize>) -> DeviceResult<Device> {
        let (addr, len) = if let Some(BAR::Memory(a, l, _, _)) = dev.bars[5] {
            (a as usize, l as usize)
        } else {
            return Err(DeviceError::NotSupported);
        };

        if addr == 0 {
            return Err(DeviceError::NotSupported);
        }

        let map_len = len.max(4096 * 8);

        if let Some(m) = mapper {
            m.query_or_map(addr, map_len);
        }

        let vaddr = phys_to_virt(addr);
        let vector = irq.map(|idx| idx + 32).unwrap_or(33);
        let blk = Arc::new(AhciInterface::new(vaddr, vector)?);
        Ok(Device::Block(blk))
    }
}
