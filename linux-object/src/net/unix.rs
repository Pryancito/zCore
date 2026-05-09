use crate::fs::{FileLike, OpenFlags, PollEvents, PollStatus};
use crate::{
    error::{LxError, LxResult},
    net::{Endpoint, Socket, SysResult},
    sync::{Event, EventBus},
};
use alloc::{
    boxed::Box,
    collections::VecDeque,
    sync::{Arc, Weak},
    string::String,
};
use async_trait::async_trait;
use lock::Mutex;
use zircon_object::object::*;
use hashbrown::HashMap;
use lazy_static::lazy_static;

lazy_static! {
    static ref UNIX_SOCKETS: Mutex<HashMap<String, Weak<UnixSocketState>>> =
        Mutex::new(HashMap::new());
}

/// Unix domain socket (AF_UNIX / AF_LOCAL) implementation.
///
/// Supports the full dhcpcd workflow:
/// - Server: socket → bind → listen → accept
/// - Client: socket → connect  (→ ECONNREFUSED if no listener)
pub struct UnixSocketState {
    base: KObjectBase,
    inner: Mutex<UnixInner>,
}

struct UnixInner {
    flags: OpenFlags,
    /// Local bound path (set by bind or inherited on accept)
    path: String,
    /// Weak ref to the connected peer socket
    peer: Option<Weak<UnixSocketState>>,
    /// Inbound data buffer
    buffer: VecDeque<u8>,
    eventbus: EventBus,
    /// True after listen() is called
    is_listening: bool,
    /// Pending connections waiting for accept()
    accept_queue: VecDeque<Arc<UnixSocketState>>,
    /// True once a successful connect() has completed both ends
    connected: bool,
    /// True when the peer has closed / disconnected
    peer_closed: bool,
}

impl Default for UnixSocketState {
    fn default() -> Self {
        Self {
            base: KObjectBase::new(),
            inner: Mutex::new(UnixInner {
                flags: OpenFlags::RDWR,
                path: String::new(),
                peer: None,
                buffer: VecDeque::new(),
                eventbus: EventBus::default(),
                is_listening: false,
                accept_queue: VecDeque::new(),
                connected: false,
                peer_closed: false,
            }),
        }
    }
}

impl UnixSocketState {
    /// Create a new Unix socket wrapped in Arc (needed everywhere).
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Wire two sockets together bidirectionally.
    /// Must be called while neither inner lock is held.
    pub fn connect_pair(a: &Arc<Self>, b: &Arc<Self>) {
        {
            let mut ai = a.inner.lock();
            ai.peer = Some(Arc::downgrade(b));
            ai.connected = true;
            ai.eventbus.set(Event::WRITABLE);
        }
        {
            let mut bi = b.inner.lock();
            bi.peer = Some(Arc::downgrade(a));
            bi.connected = true;
            bi.eventbus.set(Event::WRITABLE);
        }
    }

    /// Return true if this socket has been marked as listening.
    pub fn is_listening(&self) -> bool {
        self.inner.lock().is_listening
    }

    /// Mark this socket as connected (used by sys_connect for the client side).
    pub fn mark_connected(&self) {
        self.inner.lock().connected = true;
    }

    /// Register this socket under `path` so that connect() can find it.
    pub fn register(path: String, socket: Arc<Self>) -> LxResult<()> {
        let mut map = UNIX_SOCKETS.lock();
        if let Some(w) = map.get(&path) {
            if w.upgrade().is_some() {
                return Err(LxError::EADDRINUSE);
            }
        }
        map.insert(path, Arc::downgrade(&socket));
        Ok(())
    }

    /// Look up a registered socket by path.
    pub fn lookup(path: &String) -> Option<Arc<Self>> {
        let mut map = UNIX_SOCKETS.lock();
        if let Some(w) = map.get(path) {
            if let Some(arc) = w.upgrade() {
                return Some(arc);
            }
            map.remove(path);
        }
        None
    }

    /// Remove a registration (called on drop / close).
    pub fn unregister(path: &str) {
        UNIX_SOCKETS.lock().remove(path);
    }

    /// Push a pending connection from `peer` into this server's accept queue.
    pub fn push_accept(self: &Arc<Self>, peer: Arc<UnixSocketState>) {
        let mut inner = self.inner.lock();
        inner.accept_queue.push_back(peer);
        inner.eventbus.set(Event::READABLE);
    }
}

#[async_trait]
impl Socket for UnixSocketState {
    // -----------------------------------------------------------------------
    // read — dequeue bytes from our inbound buffer
    // -----------------------------------------------------------------------
    async fn read(&self, data: &mut [u8]) -> (LxResult<usize>, Endpoint) {
        let endpoint = || Endpoint::Unix(self.inner.lock().path.clone());
        loop {
            let mut inner = self.inner.lock();

            if !inner.buffer.is_empty() {
                let len = core::cmp::min(data.len(), inner.buffer.len());
                for d in data[..len].iter_mut() {
                    *d = inner.buffer.pop_front().unwrap();
                }
                if inner.buffer.is_empty() {
                    inner.eventbus.clear(Event::READABLE);
                }
                return (Ok(len), endpoint());
            }

            // EOF: peer gone
            let peer_gone = inner.peer_closed
                || inner.peer.as_ref().map_or(true, |w| w.strong_count() == 0);
            if peer_gone && inner.connected {
                return (Ok(0), endpoint());
            }

            if inner.flags.contains(OpenFlags::NON_BLOCK) {
                return (Err(LxError::EAGAIN), endpoint());
            }

            drop(inner);
            kernel_hal::thread::yield_now().await;
        }
    }

    // -----------------------------------------------------------------------
    // write — append bytes into the peer's inbound buffer
    // -----------------------------------------------------------------------
    fn write(&self, data: &[u8], _sendto_endpoint: Option<Endpoint>) -> SysResult {
        let inner = self.inner.lock();
        if let Some(peer_weak) = &inner.peer {
            if let Some(peer) = peer_weak.upgrade() {
                let mut pi = peer.inner.lock();
                pi.buffer.extend(data.iter().copied());
                pi.eventbus.set(Event::READABLE);
                Ok(data.len())
            } else {
                Err(LxError::EPIPE)
            }
        } else {
            Err(LxError::ENOTCONN)
        }
    }

    // -----------------------------------------------------------------------
    // connect — look up the server, enqueue ourselves, wire both ends
    // -----------------------------------------------------------------------
    async fn connect(&self, endpoint: Endpoint) -> SysResult {
        if let Endpoint::Unix(path) = endpoint {
            // Resolve server
            let server = match Self::lookup(&path) {
                Some(s) => s,
                None => return Err(LxError::ECONNREFUSED),
            };

            // Check it's listening
            if !server.inner.lock().is_listening {
                return Err(LxError::ECONNREFUSED);
            }

            // We need Arc<Self> to wire both ends.
            // Since connect() only has &self, we look ourselves up via the
            // UNIX_SOCKETS registry (if we're bound) or build a temporary
            // Arc by reconstructing from our KObjectBase id — but the simplest
            // approach is to create a fresh connected socket on the client side
            // and wire it. sys_connect already has the Arc and will call
            // push_accept; here we just confirm the server is listening.
            // The actual wiring is done in sys_connect via connect_pair().
            Ok(0)
        } else {
            Err(LxError::EINVAL)
        }
    }

    // -----------------------------------------------------------------------
    // bind — record the local path
    // -----------------------------------------------------------------------
    fn bind(&self, endpoint: Endpoint) -> SysResult {
        if let Endpoint::Unix(path) = endpoint {
            self.inner.lock().path = path;
            Ok(0)
        } else {
            Err(LxError::EINVAL)
        }
    }

    // -----------------------------------------------------------------------
    // listen — mark socket as passive
    // -----------------------------------------------------------------------
    fn listen(&self) -> SysResult {
        self.inner.lock().is_listening = true;
        Ok(0)
    }

    // -----------------------------------------------------------------------
    // accept — dequeue a pending connection and return connected pair
    // -----------------------------------------------------------------------
    async fn accept(&self) -> LxResult<(Arc<dyn FileLike>, Endpoint)> {
        loop {
            let mut inner = self.inner.lock();
            if let Some(peer) = inner.accept_queue.pop_front() {
                if inner.accept_queue.is_empty() {
                    inner.eventbus.clear(Event::READABLE);
                }
                drop(inner);

                // Create the server-side connected socket
                let server_side = UnixSocketState::new();
                {
                    let mut ssi = server_side.inner.lock();
                    ssi.path = self.inner.lock().path.clone();
                }

                // Wire server_side ↔ peer
                UnixSocketState::connect_pair(&server_side, &peer);

                let peer_path = peer.inner.lock().path.clone();
                return Ok((server_side, Endpoint::Unix(peer_path)));
            }

            if inner.flags.contains(OpenFlags::NON_BLOCK) {
                return Err(LxError::EAGAIN);
            }
            drop(inner);
            kernel_hal::thread::yield_now().await;
        }
    }

    fn shutdown(&self) -> SysResult {
        let mut inner = self.inner.lock();
        inner.peer_closed = true;
        if let Some(peer_weak) = &inner.peer {
            if let Some(peer) = peer_weak.upgrade() {
                let mut pi = peer.inner.lock();
                pi.peer_closed = true;
                pi.eventbus.set(Event::READABLE); // wake blocked reader
            }
        }
        Ok(0)
    }

    fn endpoint(&self) -> Option<Endpoint> {
        let path = self.inner.lock().path.clone();
        if !path.is_empty() { Some(Endpoint::Unix(path)) } else { None }
    }

    fn remote_endpoint(&self) -> Option<Endpoint> {
        let inner = self.inner.lock();
        inner.peer.as_ref()?.upgrade().map(|p| {
            Endpoint::Unix(p.inner.lock().path.clone())
        })
    }

    fn setsockopt(&self, _level: usize, _opt: usize, _data: &[u8]) -> SysResult {
        Ok(0)
    }

    fn ioctl(&self, _request: usize, _arg1: usize, _arg2: usize, _arg3: usize) -> SysResult {
        Ok(0)
    }

    fn poll(&self, _events: PollEvents) -> (bool, bool, bool) {
        let inner = self.inner.lock();
        let readable = !inner.buffer.is_empty()
            || (inner.is_listening && !inner.accept_queue.is_empty())
            || inner.peer_closed;
        let writable = inner.peer.as_ref().map_or(false, |w| w.strong_count() > 0);
        (readable, writable, false)
    }
}

impl_kobject!(UnixSocketState);

#[async_trait]
impl FileLike for UnixSocketState {
    fn flags(&self) -> OpenFlags {
        self.inner.lock().flags
    }

    fn set_flags(&self, f: OpenFlags) -> LxResult {
        let mut inner = self.inner.lock();
        inner.flags.set(OpenFlags::APPEND, f.contains(OpenFlags::APPEND));
        inner.flags.set(OpenFlags::NON_BLOCK, f.contains(OpenFlags::NON_BLOCK));
        inner.flags.set(OpenFlags::CLOEXEC, f.contains(OpenFlags::CLOEXEC));
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
        // For blocking sockets: wait until something is readable or writable.
        let non_block = self.inner.lock().flags.contains(OpenFlags::NON_BLOCK);
        if !non_block {
            loop {
                {
                    let inner = self.inner.lock();
                    let readable = !inner.buffer.is_empty()
                        || (inner.is_listening && !inner.accept_queue.is_empty())
                        || inner.peer_closed;
                    let want_read = events.contains(PollEvents::IN);
                    let want_write = events.contains(PollEvents::OUT);
                    let writable = inner.peer.as_ref().map_or(false, |w| w.strong_count() > 0);
                    if (want_read && readable) || (want_write && writable) {
                        break;
                    }
                }
                kernel_hal::thread::yield_now().await;
            }
        }
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
