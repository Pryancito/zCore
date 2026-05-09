use crate::{
    error::{LxError, LxResult},
    fs::{FileLike, OpenFlags, PollEvents, PollStatus},
    net::*,
};
use alloc::boxed::Box;
use async_trait::async_trait;
use kernel_hal::drivers;
use zircon_object::object::*;

/// A minimal AF_PACKET socket backed by the first NetScheme device.
///
/// This is enough for BusyBox `udhcpc` to create its raw socket.
pub struct PacketSocketState {
    base: KObjectBase,
    flags: lock::Mutex<OpenFlags>,
}

impl PacketSocketState {
    pub fn new() -> Self {
        Self {
            base: KObjectBase::new(),
            flags: lock::Mutex::new(OpenFlags::RDWR),
        }
    }
}

#[async_trait]
impl Socket for PacketSocketState {
    async fn read(&self, data: &mut [u8]) -> (SysResult, Endpoint) {
        // Best-effort: try to receive one frame.
        // If there is no net device (or no data), behave like non-blocking read would.
        let dev = match drivers::all_net().first() {
            Some(dev) => dev,
            None => {
                return (
                    Err(LxError::ENODEV),
                    Endpoint::Ip(smoltcp::wire::IpEndpoint::UNSPECIFIED),
                )
            }
        };
        match dev.recv(data) {
            Ok(n) if n > 0 => (Ok(n), Endpoint::Ip(smoltcp::wire::IpEndpoint::UNSPECIFIED)),
            _ => (
                Err(LxError::EAGAIN),
                Endpoint::Ip(smoltcp::wire::IpEndpoint::UNSPECIFIED),
            ),
        }
    }

    fn write(&self, data: &[u8], _sendto_endpoint: Option<Endpoint>) -> SysResult {
        let dev = drivers::all_net().first().ok_or(LxError::ENODEV)?;
        dev.send(data).map_err(|_| LxError::EIO)?;
        Ok(data.len())
    }

    async fn connect(&self, _endpoint: Endpoint) -> SysResult {
        Err(LxError::EINVAL)
    }

    fn bind(&self, _endpoint: Endpoint) -> SysResult {
        Ok(0)
    }

    fn setsockopt(&self, _level: usize, _opt: usize, _data: &[u8]) -> SysResult {
        Ok(0)
    }

    fn poll(&self, _events: PollEvents) -> (bool, bool, bool) {
        let dev = drivers::all_net().first();
        let readable = dev.as_ref().map(|d| d.can_recv()).unwrap_or(false);
        let writable = dev.as_ref().map(|d| d.can_send()).unwrap_or(false);
        (readable, writable, false)
    }

    fn ioctl(&self, _request: usize, _arg1: usize, _arg2: usize, _arg3: usize) -> SysResult {
        Ok(0)
    }

    fn socket_type(&self) -> Option<SocketType> {
        Some(SocketType::SOCK_RAW)
    }
}

impl_kobject!(PacketSocketState);

#[async_trait]
impl FileLike for PacketSocketState {
    fn flags(&self) -> OpenFlags {
        *self.flags.lock()
    }

    fn set_flags(&self, f: OpenFlags) -> LxResult {
        let flags = &mut *self.flags.lock();
        flags.set(OpenFlags::APPEND, f.contains(OpenFlags::APPEND));
        flags.set(OpenFlags::NON_BLOCK, f.contains(OpenFlags::NON_BLOCK));
        flags.set(OpenFlags::CLOEXEC, f.contains(OpenFlags::CLOEXEC));
        Ok(())
    }

    async fn read(&self, buf: &mut [u8]) -> LxResult<usize> {
        Socket::read(self, buf).await.0
    }

    async fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> LxResult<usize> {
        unimplemented!()
    }

    fn write(&self, buf: &[u8]) -> LxResult<usize> {
        Socket::write(self, buf, None)
    }

    fn poll(&self, events: PollEvents) -> LxResult<PollStatus> {
        let (read, write, error) = Socket::poll(self, events);
        Ok(PollStatus { read, write, error })
    }

    async fn async_poll(&self, events: PollEvents) -> LxResult<PollStatus> {
        let (read, write, error) = Socket::poll(self, events);
        Ok(PollStatus { read, write, error })
    }

    fn ioctl(&self, request: usize, arg1: usize, arg2: usize, arg3: usize) -> LxResult<usize> {
        Socket::ioctl(self, request, arg1, arg2, arg3)
    }

    fn as_socket(&self) -> LxResult<&dyn Socket> {
        Ok(self)
    }
}
