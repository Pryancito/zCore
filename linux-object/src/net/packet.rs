use crate::{
    error::{LxError, LxResult},
    fs::{FileLike, OpenFlags, PollEvents, PollStatus},
    net::*,
};
use alloc::{boxed::Box, collections::VecDeque, sync::Arc, vec, vec::Vec};
use async_trait::async_trait;
use kernel_hal::{drivers, thread};
use lock::Mutex;
use zircon_object::object::*;

// Maximum raw ethernet frame size
const MAX_FRAME: usize = 1536;
// Maximum number of buffered frames to prevent unbounded memory growth
const MAX_RX_QUEUE: usize = 64;

/// AF_PACKET socket backed by the first available NetScheme device.
///
/// Supports both udhcpc (BusyBox) and other raw-socket DHCP clients.
/// Frames sent by userland go directly to the wire; frames from the
/// wire are buffered in `rx_queue` and dequeued by blocking read().
pub struct PacketSocketState {
    base: KObjectBase,
    flags: Mutex<OpenFlags>,
    /// Buffered received frames (raw ethernet, up to MAX_FRAME bytes each).
    /// Uses VecDeque for FIFO ordering — oldest frame is dequeued first.
    rx_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    /// Index (1-based) of the bound interface; 0 = unbound.
    ifindex: Mutex<u32>,
}

impl PacketSocketState {
    pub fn new() -> Self {
        Self {
            base: KObjectBase::new(),
            flags: Mutex::new(OpenFlags::RDWR),
            rx_queue: Arc::new(Mutex::new(VecDeque::new())),
            ifindex: Mutex::new(0),
        }
    }

    /// Try to pull one frame from the hardware and place it in rx_queue.
    /// Returns true if a frame was queued.
    fn try_recv_one(&self) -> bool {
        let dev = match drivers::all_net().first() {
            Some(d) => d,
            None => return false,
        };
        let mut buf = vec![0u8; MAX_FRAME];
        match dev.recv(&mut buf) {
            Ok(n) if n > 0 => {
                buf.truncate(n);
                let mut q = self.rx_queue.lock();
                // Drop oldest frame if queue is full to avoid unbounded growth
                if q.len() >= MAX_RX_QUEUE {
                    q.pop_front();
                }
                q.push_back(buf);
                true
            }
            _ => false,
        }
    }

    /// Drain all available frames from hardware into rx_queue.
    fn drain_hw(&self) {
        // Pull up to MAX_RX_QUEUE frames in one batch
        for _ in 0..MAX_RX_QUEUE {
            if !self.try_recv_one() {
                break;
            }
        }
    }
}

#[async_trait]
impl Socket for PacketSocketState {
    /// Blocking read: polls hardware until a frame arrives, then returns it.
    async fn read(&self, data: &mut [u8]) -> (SysResult, Endpoint) {
        let endpoint = Endpoint::Ip(smoltcp::wire::IpEndpoint::UNSPECIFIED);
        let non_block = self.flags.lock().contains(OpenFlags::NON_BLOCK);

        loop {
            // Drain any available frames from hardware into our queue.
            self.drain_hw();

            // Try to get a buffered frame (FIFO order).
            let maybe_frame = self.rx_queue.lock().pop_front();
            if let Some(frame) = maybe_frame {
                let n = core::cmp::min(frame.len(), data.len());
                data[..n].copy_from_slice(&frame[..n]);
                return (Ok(n), endpoint);
            }

            if non_block {
                return (Err(LxError::EAGAIN), endpoint);
            }

            // Nothing available yet — yield and retry.
            thread::yield_now().await;
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

    fn bind(&self, endpoint: Endpoint) -> SysResult {
        if let Endpoint::LinkLevel(ll) = endpoint {
            *self.ifindex.lock() = ll.interface_index as u32;
        }
        Ok(0)
    }

    fn setsockopt(&self, _level: usize, _opt: usize, _data: &[u8]) -> SysResult {
        Ok(0)
    }

    fn poll(&self, _events: PollEvents) -> (bool, bool, bool) {
        // Try to pull frames so that subsequent read() can find them.
        self.drain_hw();
        let readable = !self.rx_queue.lock().is_empty();
        let writable = drivers::all_net()
            .first()
            .as_ref()
            .map(|d| d.can_send())
            .unwrap_or(false);
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
        Err(LxError::ESPIPE)
    }

    fn write(&self, buf: &[u8]) -> LxResult<usize> {
        Socket::write(self, buf, None)
    }

    fn poll(&self, events: PollEvents) -> LxResult<PollStatus> {
        let (read, write, error) = Socket::poll(self, events);
        Ok(PollStatus { read, write, error })
    }

    async fn async_poll(&self, events: PollEvents) -> LxResult<PollStatus> {
        // Non-blocking snapshot — try to pull frames, then report state.
        // select() / poll() syscalls handle blocking/timeout externally.
        self.drain_hw();
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
