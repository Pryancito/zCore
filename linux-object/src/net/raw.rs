use crate::{
    error::{LxError, LxResult},
    fs::{FileLike, OpenFlags, PollEvents, PollStatus},
    net::*,
};
use alloc::boxed::Box;
use alloc::sync::Arc;
use async_trait::async_trait;
use kernel_hal::thread;
use lock::Mutex;
use smoltcp::{
    socket::{RawPacketMetadata, RawSocket, RawSocketBuffer},
    wire::{IpProtocol, IpVersion, Ipv4Address, Ipv4Packet},
};

// Needed by `impl_kobject!`
#[allow(unused_imports)]
use zircon_object::object::*;

pub struct RawSocketState {
    base: KObjectBase,
    inner: Arc<RawSocketInner>,
}

#[derive(Debug)]
struct RawSocketInner {
    handle: GlobalSocketHandle,
    header_included: Mutex<bool>,
    flags: Mutex<OpenFlags>,
}

impl RawSocketState {
    /// missing documentation
    pub fn new(protocol: u8) -> Self {
        let rx_buffer = RawSocketBuffer::new(
            vec![RawPacketMetadata::EMPTY; RAW_METADATA_BUF],
            vec![0; RAW_RECVBUF],
        );
        let tx_buffer = RawSocketBuffer::new(
            vec![RawPacketMetadata::EMPTY; RAW_METADATA_BUF],
            vec![0; RAW_SENDBUF],
        );
        let socket = RawSocket::new(
            IpVersion::Ipv4,
            IpProtocol::from(protocol),
            rx_buffer,
            tx_buffer,
        );
        let handle = GlobalSocketHandle(get_sockets().lock().add(socket));

        RawSocketState {
            base: KObjectBase::new(),
            inner: Arc::new(RawSocketInner {
                handle,
                header_included: Mutex::new(false),
                flags: Mutex::new(OpenFlags::RDWR),
            }),
        }
    }
}

/// missing in implementation
#[async_trait]
impl Socket for RawSocketState {
    async fn read(&self, data: &mut [u8]) -> (SysResult, Endpoint) {
        info!("raw read");
        loop {
            info!("raw read loop");
            poll_ifaces();
            let net_sockets = get_sockets();
            let mut sockets = net_sockets.lock();
            let mut socket = sockets.get::<RawSocket>(self.inner.handle.0);
            if socket.can_recv() {
                if let Ok(size) = socket.recv_slice(data) {
                    let packet = Ipv4Packet::new_unchecked(data);
                    // avoid deadlock
                    drop(socket);
                    drop(sockets);
                    poll_ifaces();
                    return (
                        Ok(size),
                        Endpoint::Ip(IpEndpoint {
                            addr: IpAddress::Ipv4(packet.src_addr()),
                            port: 0,
                        }),
                    );
                }
            }
            let non_block = self.inner.flags.lock().contains(OpenFlags::NON_BLOCK);
            drop(socket);
            drop(sockets);
            if non_block {
                return (
                    Err(LxError::EAGAIN),
                    Endpoint::Ip(IpEndpoint::UNSPECIFIED),
                );
            }
            thread::yield_now().await;
        }
    }

    fn write(&self, data: &[u8], sendto_endpoint: Option<Endpoint>) -> SysResult {
        info!("raw write");
        let net_sockets = get_sockets();
        let mut sockets = net_sockets.lock();
        let mut socket = sockets.get::<RawSocket>(self.inner.handle.0);
        if *self.inner.header_included.lock() {
            match socket.send_slice(data) {
                Ok(()) => Ok(data.len()),
                Err(_) => Err(LxError::ENOBUFS),
            }
        } else if let Some(Endpoint::Ip(endpoint)) = sendto_endpoint {
            let ifaces = kernel_hal::drivers::all_net();
            let v4_src = if let Some(iface) = ifaces.first() {
                iface.get_ip_address().into_iter().find_map(|cidr| {
                    match cidr {
                        smoltcp::wire::IpCidr::Ipv4(ipv4) => Some(ipv4.address()),
                        _ => None,
                    }
                }).unwrap_or(Ipv4Address::new(10, 0, 2, 15))
            } else {
                Ipv4Address::new(127, 0, 0, 1)
            };

            if let IpAddress::Ipv4(v4_dst) = endpoint.addr {
                let len = data.len();
                // using 20-byte IPv4 header
                let mut buffer = vec![0u8; len + 20];
                let mut packet = Ipv4Packet::new_unchecked(&mut buffer);
                packet.set_version(4);
                packet.set_header_len(20);
                packet.set_total_len((20 + len) as u16);
                packet.set_protocol(socket.ip_protocol());
                packet.set_src_addr(v4_src);
                packet.set_dst_addr(v4_dst);
                let payload = packet.payload_mut();
                payload.copy_from_slice(data);
                packet.fill_checksum();

                socket.send_slice(&buffer).unwrap();

                // avoid deadlock
                drop(socket);
                drop(sockets);
                Ok(len)
            } else {
                unimplemented!("ip type")
            }
        } else {
            Err(LxError::ENOTCONN)
        }
    }

    async fn connect(&self, _endpoint: Endpoint) -> SysResult {
        unimplemented!()
    }

    fn setsockopt(&self, level: usize, opt: usize, data: &[u8]) -> SysResult {
        match (level, opt) {
            (IPPROTO_IP, IP_HDRINCL) => {
                if let Some(arg) = data.first() {
                    *self.inner.header_included.lock() = *arg > 0;
                    debug!("hdrincl set to {}", *self.inner.header_included.lock());
                }
            }
            _ => {}
        }
        Ok(0)
    }
    fn get_buffer_capacity(&self) -> Option<(usize, usize)> {
        let sockets = get_sockets();
        let mut s = sockets.lock();
        let socket = s.get::<RawSocket>(self.inner.handle.0);
        let (recv_ca, send_ca) = (
            socket.payload_recv_capacity(),
            socket.payload_send_capacity(),
        );
        Some((recv_ca, send_ca))
    }
    fn socket_type(&self) -> Option<SocketType> {
        Some(SocketType::SOCK_RAW)
    }

    fn poll(&self, _events: PollEvents) -> (bool, bool, bool) {
        // Minimal implementation: raw sockets are generally writable,
        // and readable if the underlying smoltcp socket can recv.
        let s = get_sockets();
        let mut s = s.lock();
        let socket = s.get::<RawSocket>(self.inner.handle.0);
        (socket.can_recv(), socket.can_send(), false)
    }
}

zircon_object::impl_kobject!(RawSocketState);

#[async_trait]
impl FileLike for RawSocketState {
    fn flags(&self) -> OpenFlags {
        *self.inner.flags.lock()
    }

    fn set_flags(&self, f: OpenFlags) -> LxResult {
        let mut flags = self.inner.flags.lock();
        flags.set(OpenFlags::APPEND, f.contains(OpenFlags::APPEND));
        flags.set(OpenFlags::NON_BLOCK, f.contains(OpenFlags::NON_BLOCK));
        flags.set(OpenFlags::CLOEXEC, f.contains(OpenFlags::CLOEXEC));
        Ok(())
    }

    fn dup(&self) -> Arc<dyn FileLike> {
        Arc::new(Self {
            base: KObjectBase::new(),
            inner: self.inner.clone(),
        })
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
