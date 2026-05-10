//! Linux ELF Program Loader
#![deny(missing_docs)]

use {
    crate::error::LxResult,
    crate::fs::INodeExt,
    alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec},
    rcore_fs::vfs::INode,
    xmas_elf::ElfFile,
    zircon_object::{util::elf_loader::*, vm::*, ZxError},
};

/// Stack top: place the user stack at the very top of the user address space so
/// that the heap (at `initial_brk` just after the loaded image) never collides
/// with the stack.  Linux uses a similar high-address default for the stack.
const STACK_TOP: usize = USER_ASPACE_BASE as usize + USER_ASPACE_SIZE as usize;

mod abi;

/// Linux ELF Program Loader.
pub struct LinuxElfLoader {
    /// syscall entry
    pub syscall_entry: usize,
    /// stack page number
    pub stack_pages: usize,
    /// root inode of LinuxElfLoader
    pub root_inode: Arc<dyn INode>,
}

impl LinuxElfLoader {
    /// load a Linux ElfFile and return a tuple of (entry, sp, brk)
    ///
    /// `brk` is the initial program break (end of the loaded image, page-aligned).
    /// Callers should store it on the process with `proc.linux().set_brk(brk)`.
    pub fn load(
        &self,
        vmar: &Arc<VmAddressRegion>,
        data: &[u8],
        args: Vec<String>,
        envs: Vec<String>,
        path: String,
    ) -> LxResult<(VirtAddr, VirtAddr, usize)> {
        self.load_impl(vmar, data, args, envs, path, 0)
    }

    /// Maximum number of interpreter levels (shebang + ELF PT_INTERP combined).
    const MAX_INTERP_DEPTH: usize = 4;

    /// Internal recursive loader that tracks interpreter depth.
    fn load_impl(
        &self,
        vmar: &Arc<VmAddressRegion>,
        data: &[u8],
        args: Vec<String>,
        envs: Vec<String>,
        path: String,
        recursion: u8,
    ) -> LxResult<(VirtAddr, VirtAddr, usize)> {
        debug!("elf: load_impl recursion={} len={:#x} path={:?}", recursion, data.len(), path);
        debug!(
            "load: vmar.addr & size: {:#x?}, data {:#x?}, args: {:?}, envs: {:?}",
            vmar.get_info(),
            data.as_ptr(),
            args,
            envs
        );

        if recursion as usize > Self::MAX_INTERP_DEPTH {
            error!("load: interpreter chain too deep (depth={})", recursion);
            return Err(ZxError::INVALID_ARGS.into());
        }

        // Handle shebang scripts (#!).
        // Limit scan to the first 512 bytes to match typical OS shebang length restrictions.
        if data.starts_with(b"\x7fELF") {
            debug!("elf: detected ELF for {:?}", path);
        } else if data.starts_with(b"#!") {
            debug!("elf: detected shebang for {:?}", path);
            let scan_limit = data.len().min(512);
            let newline = data[..scan_limit]
                .iter()
                .position(|&b| b == b'\n')
                .unwrap_or(scan_limit);
            let line = core::str::from_utf8(&data[2..newline])
                .map_err(|_| ZxError::INVALID_ARGS)?
                .trim_end_matches('\r')
                .trim();
            // Split only on ASCII space/tab (POSIX shebang convention).
            let mut parts = line.splitn(2, |c: char| c == ' ' || c == '\t');
            let interp = match parts.next() {
                Some(i) if !i.is_empty() => i,
                _ => return Err(ZxError::INVALID_ARGS.into()),
            };
            let interp_arg = parts.next().map(|s| s.trim()).filter(|s| !s.is_empty());
            debug!(
                "shebang: interp={:?}, arg={:?}, script={:?}",
                interp, interp_arg, path
            );
            let interp_rel = interp.trim_start_matches('/');
            let inode = self.root_inode.lookup(interp_rel).map_err(|e| {
                error!("shebang: lookup interp {:?} failed: {:?}", interp_rel, e);
                e
            })?;
            let interp_data = inode.read_as_vec().map_err(|e| {
                error!("shebang: read interp {:?} failed: {:?}", interp_rel, e);
                e
            })?;
            let interp_path: String = interp.into();
            let mut new_args = vec![interp_path.clone()];
            if let Some(arg) = interp_arg {
                new_args.push(arg.into());
            }
            new_args.push(path);
            new_args.extend_from_slice(args.get(1..).unwrap_or_default());
            return self.load_impl(vmar, &interp_data, new_args, envs, interp_path, recursion + 1);
        }

        let elf = ElfFile::new(data).map_err(|_| ZxError::INVALID_ARGS)?;

        debug!("elf info:  {:#x?}", elf.header.pt2);

        if let Ok(interp) = elf.get_interpreter() {
            info!("interp: {:?}, path: {:?}", interp, path);

            // Load the main program into the first sub-VMAR (allocated at offset 0 in an
            // empty address space, so app_base is typically 0 for a non-PIE binary).
            let app_size = elf.load_segment_size();
            let app_vmar = vmar.allocate(None, app_size, VmarFlags::CAN_MAP_RXW, PAGE_SIZE).map_err(|e| {
                error!("elf: allocate vmar for app size {:#x} failed: {:?}", app_size, e);
                e
            })?;
            let app_base = app_vmar.addr();
            let app_vmo = app_vmar.load_from_elf(&elf).map_err(|e| {
                error!("elf: load app from elf failed: {:?}", e);
                e
            })?;
            let app_entry = app_base + elf.header.pt2.entry_point() as usize;

            // Patch any in-binary syscall-entry trampoline present in the main program.
            if let Some(offset) = elf.get_symbol_address("rcore_syscall_entry") {
                app_vmo.write(offset as usize, &self.syscall_entry.to_ne_bytes())?;
            }

            // Load the interpreter (ld.so) into a second sub-VMAR placed right after the
            // main program.  Because app_vmar occupies [0, app_size), the allocator places
            // interp_vmar at interp_base = app_size (> 0).
            //
            // A non-zero AT_BASE tells musl/glibc it is running as a PT_INTERP interpreter
            // rather than in standalone mode.  In interpreter mode the dynamic linker uses
            // the already-kernel-mapped binary via AT_PHDR / AT_ENTRY instead of calling
            // mmap() from user space to re-load it – which is the path that breaks in the
            // fork+execve case and causes a page fault at the raw e_entry (e.g. 0x423a7).
            let inode = self.root_inode.lookup(interp).map_err(|e| {
                error!("elf: lookup interp {:?} failed: {:?}", interp, e);
                e
            })?;
            let interp_data = inode.read_as_vec()?;
            let interp_elf = ElfFile::new(&interp_data).map_err(|_| {
                error!("elf: interp {:?} is not a valid ELF", interp);
                ZxError::INVALID_ARGS
            })?;
            let interp_size = interp_elf.load_segment_size();
            let interp_vmar =
                vmar.allocate(None, interp_size, VmarFlags::CAN_MAP_RXW, PAGE_SIZE).map_err(|e| {
                    error!("elf: allocate vmar for interp {:?} size {:#x} failed: {:?}", interp, interp_size, e);
                    e
                })?;
            let interp_base = interp_vmar.addr();
            let _interp_vmo = interp_vmar.load_from_elf(&interp_elf).map_err(|e| {
                error!("elf: load interp {:?} from elf failed: {:?}", interp, e);
                e
            })?;
            let interp_entry = interp_base + interp_elf.header.pt2.entry_point() as usize;

            match interp_elf.relocate(interp_vmar) {
                Ok(()) => info!("interp relocate passed!"),
                Err(e) => {
                    warn!(
                        "interp relocate Err: {:?}, keeping base {:#x}",
                        e, interp_base
                    )
                }
            }

            let stack_vmo = VmObject::new_paged(self.stack_pages);
            let stack_flags = MMUFlags::READ | MMUFlags::WRITE | MMUFlags::USER;
            // Place the stack at the top of the user address space so the heap
            // (which grows up from initial_brk) never collides with the stack.
            let stack_bottom = STACK_TOP - stack_vmo.len();
            vmar.map(
                Some(stack_bottom - vmar.addr()),
                stack_vmo.clone(),
                0,
                stack_vmo.len(),
                stack_flags,
            )?;
            let mut sp = STACK_TOP;

            let info = abi::ProcInitInfo {
                args,
                envs,
                auxv: {
                    let mut map = BTreeMap::new();
                    #[cfg(target_arch = "x86_64")]
                    {
                        // AT_BASE: interpreter load address; non-zero triggers interpreter
                        // mode in musl/glibc.
                        map.insert(abi::AT_BASE, interp_base);
                        // AT_PHDR: virtual address of the main program's program-header
                        // table in memory.  Use get_phdr_vaddr() which handles both PIE
                        // (vaddr relative to load base) and non-PIE (absolute vaddr)
                        // correctly, unlike the raw ph_offset() file field.
                        let phdr_vaddr = elf
                            .get_phdr_vaddr()
                            .unwrap_or(elf.header.pt2.ph_offset() as u64)
                            as usize;
                        map.insert(abi::AT_PHDR, app_base + phdr_vaddr);
                        // AT_ENTRY: main program's entry point.
                        map.insert(abi::AT_ENTRY, app_entry);
                    }
                    #[cfg(target_arch = "riscv64")]
                    {
                        map.insert(abi::AT_BASE, interp_base);
                        map.insert(abi::AT_ENTRY, app_entry);
                        if let Some(phdr_vaddr) = elf.get_phdr_vaddr() {
                            map.insert(abi::AT_PHDR, app_base + phdr_vaddr as usize);
                        }
                    }
                    #[cfg(target_arch = "aarch64")]
                    {
                        map.insert(abi::AT_BASE, interp_base);
                        map.insert(abi::AT_ENTRY, app_entry);
                        if let Some(phdr_vaddr) = elf.get_phdr_vaddr() {
                            map.insert(abi::AT_PHDR, app_base + phdr_vaddr as usize);
                        }
                    }
                    map.insert(abi::AT_PHENT, elf.header.pt2.ph_entry_size() as usize);
                    map.insert(abi::AT_PHNUM, elf.header.pt2.ph_count() as usize);
                    map.insert(abi::AT_PAGESZ, PAGE_SIZE);
                    map
                },
            };
            let init_stack = info.push_at(sp);
            stack_vmo.write(self.stack_pages * PAGE_SIZE - init_stack.len(), &init_stack)?;
            sp -= init_stack.len();

            // Initial brk: right after the interpreter (which is placed after the main
            // program). Using interp_base + interp_size ensures brk does not overlap
            // any already-allocated segment.
            let initial_brk = interp_base + interp_size;
            return Ok((interp_entry, sp, initial_brk));
        }

        let size = elf.load_segment_size();
        let image_vmar = vmar.allocate(None, size, VmarFlags::CAN_MAP_RXW, PAGE_SIZE)?;
        let base = image_vmar.addr();
        let vmo = image_vmar.load_from_elf(&elf)?;
        let entry = base + elf.header.pt2.entry_point() as usize;

        debug!(
            "load: vmar.addr & size: {:#x?}, base: {:#x?}, entry: {:#x?}",
            vmar.get_info(),
            base,
            entry
        );

        // fill syscall entry
        if let Some(offset) = elf.get_symbol_address("rcore_syscall_entry") {
            vmo.write(offset as usize, &self.syscall_entry.to_ne_bytes())?;
        }

        match elf.relocate(image_vmar) {
            Ok(()) => info!("elf relocate passed !"),
            Err(error) => {
                // Segments stay mapped under `image_vmar.addr()`; do not clobber `base` with the
                // first program header vaddr (often not PT_LOAD). Wrong AT_BASE breaks PIE/musl
                // (e.g. user PC stuck at raw e_entry like 0x423a7 → page fault NOT_FOUND).
                warn!(
                    "elf relocate Err:{:?}, keeping load base {:#x}",
                    error, base
                );
            }
        }

        let stack_vmo = VmObject::new_paged(self.stack_pages);
        let flags = MMUFlags::READ | MMUFlags::WRITE | MMUFlags::USER;
        // Place the stack at the top of the user address space so the heap
        // (which grows up from initial_brk) never collides with the stack.
        let stack_bottom = STACK_TOP - stack_vmo.len();
        vmar.map(
            Some(stack_bottom - vmar.addr()),
            stack_vmo.clone(),
            0,
            stack_vmo.len(),
            flags,
        )?;
        let mut sp = STACK_TOP;
        debug!("load stack bottom: {:#x}", stack_bottom);

        let info = abi::ProcInitInfo {
            args,
            envs,
            auxv: {
                let mut map = BTreeMap::new();
                #[cfg(target_arch = "x86_64")]
                {
                    // AT_BASE: interpreter load address; 0 means no interpreter (static binary).
                    map.insert(abi::AT_BASE, 0usize);
                    // AT_PHDR: virtual address of program headers in memory.
                    // Use get_phdr_vaddr() which handles both PIE and non-PIE correctly.
                    // If None, the ELF has no loadable segment covering the program headers
                    // (degenerate case warned about inside get_phdr_vaddr()); fall back to
                    // ph_offset() as a best-effort value — AT_PHDR is optional for static
                    // binaries and musl only uses it for TLS initialisation.
                    let phdr_vaddr = elf
                        .get_phdr_vaddr()
                        .unwrap_or(elf.header.pt2.ph_offset() as u64)
                        as usize;
                    map.insert(abi::AT_PHDR, base + phdr_vaddr);
                    map.insert(abi::AT_ENTRY, entry);
                }
                #[cfg(target_arch = "riscv64")]
                if let Some(phdr_vaddr) = elf.get_phdr_vaddr() {
                    map.insert(abi::AT_PHDR, base + phdr_vaddr as usize);
                }
                #[cfg(target_arch = "aarch64")]
                {
                    // AT_BASE: 0 means no interpreter (static binary).
                    map.insert(abi::AT_BASE, 0usize);
                    map.insert(abi::AT_ENTRY, entry);
                    if let Some(phdr_vaddr) = elf.get_phdr_vaddr() {
                        map.insert(abi::AT_PHDR, base + phdr_vaddr as usize);
                    }
                }
                map.insert(abi::AT_PHENT, elf.header.pt2.ph_entry_size() as usize);
                map.insert(abi::AT_PHNUM, elf.header.pt2.ph_count() as usize);
                map.insert(abi::AT_PAGESZ, PAGE_SIZE);
                map
            },
        };
        let init_stack = info.push_at(sp);
        stack_vmo.write(self.stack_pages * PAGE_SIZE - init_stack.len(), &init_stack)?;
        sp -= init_stack.len();

        debug!(
            "ProcInitInfo auxv: {:#x?}\nentry:{:#x}, sp:{:#x}",
            info.auxv, entry, sp
        );

        // Initial brk: right after the loaded image.
        let initial_brk = base + size;
        Ok((entry, sp, initial_brk))
    }
}
