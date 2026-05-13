use alloc::{boxed::Box, collections::VecDeque, vec, vec::Vec};
use core::ops::{Deref, DerefMut};
use lock::Mutex;
use smoltcp::socket::{SocketHandle, SocketSet};
use smoltcp::socket::{TcpSocket, TcpSocketBuffer, TcpState};
use smoltcp::wire::{IpAddress, IpEndpoint};
use zcore_drivers::net::get_sockets;
use crate::error::{LxError, LxResult};

const LISTEN_QUEUE_SIZE: usize = 64;
const PORT_NUM: usize = 65536;

pub struct ListenTableEntry {
    pub listen_endpoint: IpEndpoint,
    pub syn_queue: VecDeque<SocketHandle>,
}

impl ListenTableEntry {
    pub fn new(listen_endpoint: IpEndpoint) -> Self {
        Self {
            listen_endpoint,
            syn_queue: VecDeque::with_capacity(LISTEN_QUEUE_SIZE),
        }
    }

    #[inline]
    fn can_accept(&self, dst: IpAddress) -> bool {
        if self.listen_endpoint.addr == IpAddress::Unspecified {
            true
        } else {
            self.listen_endpoint.addr == dst
        }
    }
}

impl Drop for ListenTableEntry {
    fn drop(&mut self) {
        let sockets_arc = get_sockets();
        let mut sockets = sockets_arc.lock();
        for &handle in &self.syn_queue {
            sockets.remove(handle);
        }
    }
}

pub struct ListenTable {
    tcp: Box<[Mutex<Option<Box<ListenTableEntry>>>]>,
}

impl ListenTable {
    pub fn new() -> Self {
        let mut vec = Vec::with_capacity(PORT_NUM);
        for _ in 0..PORT_NUM {
            vec.push(Mutex::new(None));
        }
        Self {
            tcp: vec.into_boxed_slice(),
        }
    }

    pub fn can_listen(&self, port: u16) -> bool {
        self.tcp[port as usize].lock().is_none()
    }

    pub fn listen(&self, listen_endpoint: IpEndpoint) -> LxResult<()> {
        let port = listen_endpoint.port;
        if port == 0 {
            return Err(LxError::EINVAL);
        }
        let mut entry = self.tcp[port as usize].lock();
        if entry.is_none() {
            *entry = Some(Box::new(ListenTableEntry::new(listen_endpoint)));
            Ok(())
        } else {
            Err(LxError::EADDRINUSE)
        }
    }

    pub fn unlisten(&self, port: u16) {
        *self.tcp[port as usize].lock() = None;
    }

    pub fn can_accept(&self, port: u16) -> LxResult<bool> {
        if let Some(entry) = self.tcp[port as usize].lock().deref() {
            Ok(entry.syn_queue.iter().any(|&handle| is_connected(handle)))
        } else {
            Err(LxError::EINVAL)
        }
    }

    pub fn accept(&self, port: u16) -> LxResult<(SocketHandle, (IpEndpoint, IpEndpoint))> {
        if let Some(entry) = self.tcp[port as usize].lock().deref_mut() {
            let syn_queue = &mut entry.syn_queue;
            let (idx, addr_tuple) = syn_queue
                .iter()
                .enumerate()
                .find_map(|(idx, &handle)| {
                    is_connected(handle).then(|| (idx, get_addr_tuple(handle)))
                })
                .ok_or(LxError::EAGAIN)?; // wait for connection
            
            let handle = syn_queue.remove(idx).unwrap();
            Ok((handle, addr_tuple))
        } else {
            Err(LxError::EINVAL)
        }
    }

    pub fn incoming_tcp_packet(
        &self,
        _src: IpEndpoint,
        dst: IpEndpoint,
        sockets: &mut SocketSet<'_>,
    ) {
        if let Some(entry) = self.tcp[dst.port as usize].lock().deref_mut() {
            if !entry.can_accept(dst.addr) {
                return;
            }
            if entry.syn_queue.len() >= LISTEN_QUEUE_SIZE {
                return;
            }
            
            let rx_buffer = TcpSocketBuffer::new(vec![0; super::TCP_RECVBUF]);
            let tx_buffer = TcpSocketBuffer::new(vec![0; super::TCP_SENDBUF]);
            let mut socket = TcpSocket::new(rx_buffer, tx_buffer);
            
            // Listen without specific remote endpoint to accept from any
            if socket.listen(entry.listen_endpoint).is_ok() {
                let handle = sockets.add(socket);
                entry.syn_queue.push_back(handle);
            }
        }
    }
}

fn is_connected(handle: SocketHandle) -> bool {
    let sockets_arc = get_sockets();
    let mut sockets = sockets_arc.lock();
    let socket = sockets.get::<TcpSocket>(handle);
    !matches!(socket.state(), TcpState::Listen | TcpState::SynReceived)
}

fn get_addr_tuple(handle: SocketHandle) -> (IpEndpoint, IpEndpoint) {
    let sockets_arc = get_sockets();
    let mut sockets = sockets_arc.lock();
    let socket = sockets.get::<TcpSocket>(handle);
    (
        socket.local_endpoint(),
        socket.remote_endpoint(),
    )
}

lazy_static::lazy_static! {
    pub static ref LISTEN_TABLE: ListenTable = ListenTable::new();
}
