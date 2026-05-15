//! Linux file objects

mod devfs;
mod file;
pub mod ioctl;
mod pipe;
mod procfs;
mod proc_self;
mod pseudo;
mod epoll;
mod eventfd;
pub mod rcore_fs_wrapper;
pub mod stdio;

#[cfg(feature = "mock-disk")]
pub mod mock;

#[cfg(feature = "mock-disk")]
/// Start simulating the disk
pub fn mocking_block(initrd: &'static mut [u8]) -> ! {
    mock::mocking(initrd)
}

#[cfg(feature = "mock-disk")]
/// Drivers for the mock disk
pub fn mock_block() -> mock::MockBlock {
    mock::MockBlock::new()
}

use alloc::{boxed::Box, string::ToString, sync::Arc, vec::Vec};
use core::convert::TryFrom;

use async_trait::async_trait;

use kernel_hal::drivers;
use rcore_fs::vfs::{FileSystem, FileType, INode, Result};
use rcore_fs_devfs::{
    special::{NullINode, ZeroINode},
    DevFS,
};
use rcore_fs_mountfs::MountFS;
use rcore_fs_ramfs::RamFS;
use zircon_object::{object::KernelObject, vm::VmObject};

use crate::error::{LxError, LxResult};
use crate::net::Socket;
use crate::process::LinuxProcess;
use devfs::RandomINode;
use procfs::ProcFS;
use pseudo::Pseudo;

pub use file::{File, OpenFlags, PollEvents, SeekFrom};
pub use pipe::Pipe;
pub use epoll::{Epoll, EpollEvent};
pub use eventfd::EventFd;
pub use rcore_fs::vfs::{self, PollStatus};
pub use stdio::{STDIN, STDOUT};

#[async_trait]
/// Generic file interface
///
/// - Normal file, Directory
/// - Socket
/// - Epoll instance
pub trait FileLike: KernelObject + downcast_rs::DowncastSync {
    /// Returns open flags.
    fn flags(&self) -> OpenFlags;
    /// Set open flags.
    fn set_flags(&self, f: OpenFlags) -> LxResult;
    /// Duplicate the file.
    fn dup(&self) -> Arc<dyn FileLike> {
        unimplemented!()
    }
    /// read to buffer
    async fn read(&self, buf: &mut [u8]) -> LxResult<usize>;
    /// write from buffer
    fn write(&self, buf: &[u8]) -> LxResult<usize>;
    /// read to buffer at given offset
    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> LxResult<usize>;
    /// write from buffer at given offset
    fn write_at(&self, _offset: u64, _buf: &[u8]) -> LxResult<usize> {
        Err(LxError::ENOSYS)
    }
    /// wait for some event on a file descriptor
    fn poll(&self, events: PollEvents) -> LxResult<PollStatus>;
    /// wait for some event on a file descriptor use async
    async fn async_poll(&self, events: PollEvents) -> LxResult<PollStatus>;
    /// manipulates the underlying device parameters of special files
    fn ioctl(&self, _request: usize, _arg1: usize, _arg2: usize, _arg3: usize) -> LxResult<usize> {
        Err(LxError::ENOSYS)
    }
    /// Returns the [`VmObject`] representing the file with given `offset` and `len`.
    fn get_vmo(&self, _offset: usize, _len: usize) -> LxResult<Arc<VmObject>> {
        Err(LxError::ENOSYS)
    }
    /// Casting between trait objects, or use crate: cast_trait_object
    fn as_socket(&self) -> LxResult<&dyn Socket> {
        Err(LxError::ENOTSOCK)
    }
}

downcast_rs::impl_downcast!(sync FileLike);

/// file descriptor wrapper
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct FileDesc(i32);

impl FileDesc {
    /// Pathname is interpreted relative to the current working directory(CWD)
    pub const CWD: Self = FileDesc(-100);
}

impl From<usize> for FileDesc {
    fn from(x: usize) -> Self {
        FileDesc(x as i32)
    }
}

impl From<i32> for FileDesc {
    fn from(x: i32) -> Self {
        FileDesc(x)
    }
}

impl TryFrom<&str> for FileDesc {
    type Error = LxError;
    fn try_from(name: &str) -> LxResult<Self> {
        let x: i32 = name.parse().map_err(|_| LxError::EINVAL)?;
        Ok(FileDesc(x))
    }
}

impl From<FileDesc> for usize {
    fn from(f: FileDesc) -> Self {
        f.0 as _
    }
}

impl From<FileDesc> for i32 {
    fn from(f: FileDesc) -> Self {
        f.0
    }
}

/// create root filesystem, mount DevFS and RamFS
pub fn create_root_fs(rootfs: Arc<dyn FileSystem>) -> Arc<dyn INode> {
    let rootfs = MountFS::new(rootfs);
    let root = rootfs.mountpoint_root_inode();

    // create DevFS
    let devfs = DevFS::new();
    let devfs_root = devfs.root();
    devfs_root
        .add("null", Arc::new(NullINode::new()))
        .expect("failed to mknod /dev/null");
    devfs_root
        .add("zero", Arc::new(ZeroINode::new()))
        .expect("failed to mknod /dev/zero");
    devfs_root
        .add("random", Arc::new(RandomINode::new(false)))
        .expect("failed to mknod /dev/random");
    devfs_root
        .add("urandom", Arc::new(RandomINode::new(true)))
        .expect("failed to mknod /dev/urandom");
    devfs_root
        .add("shm", Arc::new(RandomINode::new(true)))
        .expect("failed to mknod /dev/shm");
    devfs_root
        .add("tty", stdio::STDIN.clone())
        .expect("failed to mknod /dev/tty");
    if let Some(display) = drivers::all_display().first() {
        use devfs::{EventDev, FbDev, MiceDev};

        // Add framebuffer device at `/dev/fb0`
        if let Err(e) = devfs_root.add("fb0", Arc::new(FbDev::new(display.clone()))) {
            warn!("failed to mknod /dev/fb0: {:?}", e);
        }

        let input_dev = devfs_root
            .add_dir("input")
            .expect("failed to mkdir /dev/input");

        // Add mouse devices at `/dev/input/mouseX` and `/dev/input/mice`
        for (id, m) in MiceDev::from_input_devices(&drivers::all_input().as_vec()) {
            let fname = id.map_or("mice".to_string(), |id| format!("mouse{}", id));
            if let Err(e) = input_dev.add(&fname, Arc::new(m)) {
                warn!("failed to mknod /dev/input/{}: {:?}", &fname, e);
            }
        }

        // Add input event devices at `/dev/input/eventX`
        for (id, i) in drivers::all_input().as_vec().iter().enumerate() {
            let fname = format!("event{}", id);
            if let Err(e) = input_dev.add(&fname, Arc::new(EventDev::new(i.clone(), id))) {
                warn!("failed to mknod /dev/input/{}: {:?}", &fname, e);
            }
        }

        // Register DRM drivers from kernel-hal
        for drm in drivers::all_drm().as_vec().iter() {
            devfs::drm::register_driver(drm.clone());
        }

        // Add DRM devices at `/dev/dri/card0`
        let dri_dev = devfs_root.add_dir("dri").expect("failed to mkdir /dev/dri");
        if let Err(e) = dri_dev.add("card0", Arc::new(devfs::DrmDev::new(0))) {
            warn!("failed to mknod /dev/dri/card0: {:?}", e);
        }
    }

    // Add uart devices at `/dev/ttyS{i}`
    for (i, uart) in drivers::all_uart().as_vec().iter().enumerate() {
        let fname = format!("ttyS{}", i);
        if let Err(e) = devfs_root.add(&fname, Arc::new(devfs::UartDev::new(i, uart.clone()))) {
            warn!("failed to mknod /dev/{}: {:?}", &fname, e);
        }
    }

    // mount DevFS at /dev
    let dev = root.find(true, "dev").unwrap_or_else(|_| {
        root.create("dev", FileType::Dir, 0o666)
            .expect("failed to mkdir /dev")
    });
    dev.mount(devfs).expect("failed to mount DevFS");

    // mount RamFS at /tmp
    let ramfs = RamFS::new();
    let tmp = root.find(true, "tmp").unwrap_or_else(|_| {
        root.create("tmp", FileType::Dir, 0o666)
            .expect("failed to mkdir /tmp")
    });
    tmp.mount(ramfs).expect("failed to mount RamFS");

    // mount RamFS at /run (essential for DHCP clients and other daemons)
    let run_ramfs = RamFS::new();
    let run = root.find(true, "run").unwrap_or_else(|_| {
        root.create("run", FileType::Dir, 0o755)
            .expect("failed to mkdir /run")
    });
    run.mount(run_ramfs).expect("failed to mount RamFS at /run");

    // Ensure /var/run exists and can be used (often it's a symlink or needs its own mount)
    if let Ok(var) = root.find(true, "var") {
        if var.find(true, "run").is_err() {
            var.create("run", FileType::Dir, 0o755).ok();
        }
    }

    // mount ProcFS at /proc
    let proc = root.find(true, "proc").unwrap_or_else(|_| {
        root.create("proc", FileType::Dir, 0o666)
            .expect("failed to mkdir /proc")
    });
    proc.mount(Arc::new(ProcFS::new()))
        .expect("failed to mount ProcFS");

    root
}

/// extension for INode
pub trait INodeExt {
    /// similar to read, but return a u8 vector
    fn read_as_vec(&self) -> Result<Vec<u8>>;
}

impl INodeExt for dyn INode {
    #[allow(unsafe_code, clippy::uninit_vec)]
    fn read_as_vec(&self) -> Result<Vec<u8>> {
        let size = self.metadata()?.size;
        let mut buf = Vec::with_capacity(size);
        unsafe {
            buf.set_len(size);
        }
        self.read_at(0, buf.as_mut_slice())?;
        Ok(buf)
    }
}

impl LinuxProcess {
    /// Lookup INode from the process.
    ///
    /// - If `path` is relative, then it is interpreted relative to the directory
    ///   referred to by the file descriptor `dirfd`.
    ///
    /// - If the `dirfd` is the special value `AT_FDCWD`, then the directory is
    ///   current working directory of the process.
    ///
    /// - If `path` is absolute, then `dirfd` is ignored.
    ///
    /// - If `follow` is true, then dereference `path` if it is a symbolic link.
    pub fn lookup_inode_at(
        &self,
        dirfd: FileDesc,
        path: &str,
        follow: bool,
    ) -> LxResult<Arc<dyn INode>> {
        debug!(
            "lookup_inode_at: dirfd: {:?}, cwd: {:?}, path: {:?}, follow: {:?}",
            dirfd,
            self.current_working_directory(),
            path,
            follow
        );
        // hard code special path
        if path == "/proc/self/exe" {
            return Ok(Arc::new(Pseudo::new(
                &self.execute_path(),
                FileType::SymLink,
            )));
        }
        if path == "/proc/self/fd" || path == "/proc/self/fd/" {
            return Ok(Arc::new(proc_self::ProcSelfFdDir {
                process: self.zircon_process().clone(),
            }));
        }
        let (fd_dir_path, fd_name) = split_path(path);
        if fd_dir_path == "/proc/self/fd" {
            let fd = FileDesc::try_from(fd_name)?;
            let file = self.get_file(fd)?;
            return Ok(Arc::new(Pseudo::new(file.path(), FileType::SymLink)));
        }

        let follow_max_depth = if follow { FOLLOW_MAX_DEPTH } else { 0 };
        if dirfd == FileDesc::CWD {
            Ok(self
                .root_inode()
                .lookup(&self.current_working_directory())?
                .lookup_follow(path, follow_max_depth)?)
        } else {
            let file = self.get_file(dirfd)?;
            Ok(file.lookup_follow(path, follow_max_depth)?)
        }
    }

    /// Lookup INode from the process.
    ///
    /// see `lookup_inode_at`
    pub fn lookup_inode(&self, path: &str) -> LxResult<Arc<dyn INode>> {
        self.lookup_inode_at(FileDesc::CWD, path, true)
    }
}

/// Split a `path` str to `(base_path, file_name)`
pub fn split_path(path: &str) -> (&str, &str) {
    let mut split = path.trim_end_matches('/').rsplitn(2, '/');
    let file_name = split.next().unwrap();
    let mut dir_path = split.next().unwrap_or(".");
    if dir_path.is_empty() {
        dir_path = "/";
    }
    (dir_path, file_name)
}

/// the max depth for following a link
const FOLLOW_MAX_DEPTH: usize = 1;
