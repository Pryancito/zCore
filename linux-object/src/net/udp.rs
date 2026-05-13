// udpsocket

use crate::error::{LxError, LxResult};
use crate::fs::{FileLike, OpenFlags, PollStatus};
use crate::net::*;
use alloc::{boxed::Box, sync::Arc, vec};
use async_trait::async_trait;
use core::{mem::size_of, slice};
use kernel_hal::net::get_net_device;
use kernel_hal::thread;
use lock::Mutex;
use smoltcp::socket::{UdpPacketMetadata, UdpSocket, UdpSocketBuffer};
use smoltcp::wire::{IpCidr, Ipv4Address, Ipv4Cidr};

// third part
#[allow(unused_imports)]
use zircon_object::impl_kobject;
#[allow(unused_imports)]
use zircon_object::object::*;

pub struct UdpSocketState {
    /// Kernel object base
    base: KObjectBase,
    /// UdpSocket Inner
    inner: Arc<Mutex<UdpInner>>,
}

/// UDP socket inner
#[derive(Debug)]
pub struct UdpInner {
    /// A wrapper for `SocketHandle`
    handle: GlobalSocketHandle,
    /// remember remote endpoint for connect fn
    remote_endpoint: Option<IpEndpoint>,
    /// flags on the socket
    flags: OpenFlags,
}

impl Default for UdpSocketState {
    fn default() -> Self {
        UdpSocketState::new()
    }
}

// Moved to mod.rs as public constants

// Moved to mod.rs as public structures


fn iface_by_name(ifname: &str) -> LxResult<Arc<dyn zcore_drivers::scheme::NetScheme>> {
    get_net_device()
        .into_iter()
        .find(|iface| iface.get_ifname() == ifname)
        .ok_or(LxError::ENODEV)
}

fn iface_ipv4_cidr(iface: &dyn zcore_drivers::scheme::NetScheme) -> Option<Ipv4Cidr> {
    iface
        .get_ip_address()
        .into_iter()
        .find_map(|cidr| match cidr {
            IpCidr::Ipv4(cidr) => Some(cidr),
            _ => None,
        })
}

fn ipv4_sockaddr(addr: Ipv4Address) -> SockAddrIn {
    SockAddrIn {
        sin_family: AddressFamily::Internet.into(),
        sin_port: 0,
        sin_addr: u32::from_ne_bytes(addr.0),
        sin_zero: [0; 8],
    }
}

fn ipv4_netmask(prefix_len: u8) -> Ipv4Address {
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len as u32)
    };
    Ipv4Address::from_bytes(&mask.to_be_bytes())
}

fn prefix_len_from_netmask(addr: Ipv4Address) -> LxResult<u8> {
    let mask = u32::from_be_bytes(addr.0);
    let prefix_len = mask.leading_ones() as u8;
    let canonical = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len as u32)
    };
    if mask != canonical {
        return Err(LxError::EINVAL);
    }
    Ok(prefix_len)
}

impl UdpSocketState {
    /// missing documentation
    pub fn new() -> Self {
        info!("udp new");
        let rx_buffer = UdpSocketBuffer::new(
            vec![UdpPacketMetadata::EMPTY; UDP_METADATA_BUF],
            vec![0; UDP_RECVBUF],
        );
        let tx_buffer = UdpSocketBuffer::new(
            vec![UdpPacketMetadata::EMPTY; UDP_METADATA_BUF],
            vec![0; UDP_SENDBUF],
        );
        let socket = UdpSocket::new(rx_buffer, tx_buffer);
        let handle = GlobalSocketHandle(get_sockets().lock().add(socket));

        UdpSocketState {
            base: KObjectBase::new(),
            inner: Arc::new(Mutex::new(UdpInner {
                handle,
                remote_endpoint: None,
                flags: OpenFlags::RDWR,
            })),
        }
    }
}

/// missing in implementation
#[async_trait]
impl Socket for UdpSocketState {
    /// read to buffer
    async fn read(&self, data: &mut [u8]) -> (SysResult, Endpoint) {
        info!("udp read");
        let inner = self.inner.lock();
        loop {
            let sets = get_sockets();
            let mut sets = sets.lock();
            let mut socket = sets.get::<UdpSocket>(inner.handle.0);
            let copied_len = socket.recv_slice(data);
            drop(socket);
            drop(sets);

            match copied_len {
                Ok((size, endpoint)) => return (Ok(size), Endpoint::Ip(endpoint)),
                Err(smoltcp::Error::Exhausted) => {
                    poll_ifaces();
                    // The receive buffer is empty. Try again later...
                    if inner.flags.contains(OpenFlags::NON_BLOCK) {
                        debug!("NON_BLOCK: Try again later...");
                        return (Err(LxError::EAGAIN), Endpoint::Ip(IpEndpoint::UNSPECIFIED));
                    } else {
                        trace!("udp Exhausted. try again")
                    }
                }
                Err(err) => {
                    error!("udp socket recv_slice error: {:?}", err);
                    return (
                        Err(LxError::ENOTCONN),
                        Endpoint::Ip(IpEndpoint::UNSPECIFIED),
                    );
                }
            }
            if let Err(e) = crate::process::check_and_deliver_tty_interrupt() {
                return (Err(e), Endpoint::Ip(IpEndpoint::UNSPECIFIED));
            }
            thread::yield_now().await;
        }
    }
    /// write from buffer
    fn write(&self, data: &[u8], sendto_endpoint: Option<Endpoint>) -> SysResult {
        info!("udp write");
        let inner = self.inner.lock();
        let remote_endpoint = {
            if let Some(Endpoint::Ip(ref endpoint)) = sendto_endpoint {
                endpoint
            } else if let Some(ref endpoint) = inner.remote_endpoint {
                endpoint
            } else {
                return Err(LxError::ENOTCONN);
            }
        };

        let sets = get_sockets();
        let mut sets = sets.lock();
        let mut socket = sets.get::<UdpSocket>(inner.handle.0);
        if socket.endpoint().port == 0 {
            if let Err(e) = socket.bind(IpEndpoint::new(IpAddress::Unspecified, get_ephemeral_port())) {
                warn!("udp bind failed: {:?}", e);
                drop(socket);
                drop(sets);
                return Err(LxError::EINVAL);
            }
        }

        let _len = socket.send_slice(data, *remote_endpoint);

        drop(socket);
        drop(sets);
        poll_ifaces();

        match _len {
            Ok(()) => Ok(data.len()),
            Err(err) => {
                warn!("udp send_slice failed: {:?}", err);
                Err(LxError::EIO)
            }
        }
    }
    /// connect
    async fn connect(&self, endpoint: Endpoint) -> SysResult {
        if let Endpoint::Ip(ip) = endpoint {
            self.inner.lock().remote_endpoint = Some(ip);
            Ok(0)
        } else {
            Err(LxError::EINVAL)
        }
    }
    /// wait for some event on a file descriptor
    fn poll(&self, events: PollEvents) -> (bool, bool, bool) {
        //poll_ifaces();

        let inner = self.inner.lock();
        let (recv_state, send_state) = {
            let sets = get_sockets();
            let mut sets = sets.lock();
            let socket = sets.get::<UdpSocket>(inner.handle.0);
            (socket.can_recv(), socket.can_send())
        };
        if (events.contains(PollEvents::IN) && !recv_state)
            || (events.contains(PollEvents::OUT) && !send_state)
        {
            poll_ifaces();
        }

        let (mut input, mut output, mut err) = (false, false, false);
        let sets = get_sockets();
        let mut sets = sets.lock();
        let socket = sets.get::<UdpSocket>(inner.handle.0);
        if !socket.is_open() {
            err = true;
        } else {
            if socket.can_recv() {
                input = true;
            }
            if socket.can_send() {
                output = true;
            }
        }
        debug!("udp poll: {:?}", (input, output, err));
        (input, output, err)
    }

    fn bind(&self, endpoint: Endpoint) -> SysResult {
        info!("udp bind");
        #[allow(irrefutable_let_patterns)]
        if let Endpoint::Ip(mut ip) = endpoint {
            if ip.port == 0 {
                ip.port = get_ephemeral_port();
            }
            let sockets = get_sockets();
            let mut set = sockets.lock();
            let mut socket = set.get::<UdpSocket>(self.inner.lock().handle.0);
            match socket.bind(ip) {
                Ok(()) => {
                    drop(socket);
                    drop(set);
                    poll_ifaces();
                    Ok(0)
                }
                Err(_) => Err(LxError::EINVAL),
            }
        } else {
            Err(LxError::EINVAL)
        }
    }
    fn listen(&self) -> SysResult {
        warn!("listen is unimplemented");
        Err(LxError::EINVAL)
    }
    fn shutdown(&self) -> SysResult {
        warn!("shutdown is unimplemented");
        Err(LxError::EINVAL)
    }
    async fn accept(&self) -> LxResult<(Arc<dyn FileLike>, Endpoint)> {
        warn!("accept is unimplemented");
        Err(LxError::EINVAL)
    }
    fn endpoint(&self) -> Option<Endpoint> {
        let net_sockets = get_sockets();
        let mut sockets = net_sockets.lock();
        let socket = sockets.get::<UdpSocket>(self.inner.lock().handle.0);

        let endpoint = socket.endpoint();
        if endpoint.port != 0 {
            Some(Endpoint::Ip(endpoint))
        } else {
            None
        }
    }
    fn remote_endpoint(&self) -> Option<Endpoint> {
        self.inner.lock().remote_endpoint.map(Endpoint::Ip)
    }
    fn setsockopt(&self, _level: usize, _opt: usize, _data: &[u8]) -> SysResult {
        warn!("setsockopt is unimplemented");
        Ok(0)
    }

    /// manipulate file descriptor
    fn ioctl(&self, request: usize, arg1: usize, _arg2: usize, _arg3: usize) -> SysResult {
        warn!("UdpSocket: ioctl request={:#x}, arg1={:#x}", request, arg1);
        match request {
            // SIOCGIFCONF: get list of interfaces
            //
            // BusyBox `ifconfig` uses this and may loop forever if `ifc_len`
            // is not updated to the number of bytes actually written.
            SIOCGIFCONF => {
                #[allow(unsafe_code)]
                let ifc = unsafe { &mut *(arg1 as *mut IfConf) };
                if ifc.ifc_len < 0 {
                    return Err(LxError::EINVAL);
                }
                let buf_bytes = ifc.ifc_len as usize;
                let req_size = size_of::<IfReq>();

                let ifaces = get_net_device();
                let max = if buf_bytes >= req_size {
                    buf_bytes / req_size
                } else {
                    0
                };
                let count = core::cmp::min(max, ifaces.len());

                #[allow(unsafe_code)]
                let out = unsafe { slice::from_raw_parts_mut(ifc.ifc_buf as *mut u8, buf_bytes) };
                for i in 0..count {
                    let iface = &ifaces[i];

                    let mut ifr_name = [0u8; 16];
                    let name = iface.get_ifname();
                    let n = core::cmp::min(15, name.as_bytes().len());
                    ifr_name[..n].copy_from_slice(&name.as_bytes()[..n]);

                    let addr = iface_ipv4_cidr(&**iface)
                        .map(|cidr| ipv4_sockaddr(cidr.address()))
                        .unwrap_or_else(|| ipv4_sockaddr(Ipv4Address::UNSPECIFIED));
                    let ifr = IfReq {
                        ifr_name,
                        ifr_ifru: IfReqUnion { addr },
                    };

                    let start = i * req_size;
                    let end = start + req_size;
                    if end <= out.len() {
                        #[allow(unsafe_code)]
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                &ifr as *const IfReq as *const u8,
                                out[start..end].as_mut_ptr(),
                                req_size,
                            );
                        }
                    }
                }

                ifc.ifc_len = (count * req_size) as i32;
                Ok(0)
            }

            SIOCGIFINDEX => {
                #[allow(unsafe_code)]
                let ifr = unsafe { &mut *(arg1 as *mut IfReq) };
                let ifname = ifreq_name(&ifr.ifr_name)?;
                let ifaces = kernel_hal::drivers::all_net();
                for (i, iface) in ifaces.as_vec().iter().enumerate() {
                    if iface.get_ifname() == ifname {
                        ifr.ifr_ifru = IfReqUnion { ifindex: (i + 1) as i32 };
                        return Ok(0);
                    }
                }
                error!("  NOT FOUND!");
                Err(LxError::ENODEV)
            }

            // SIOCGIFFLAGS: get interface flags
            SIOCGIFFLAGS => {
                #[allow(unsafe_code)]
                let ifr = unsafe { &mut *(arg1 as *mut IfReq) };
                ifr.ifr_ifru = IfReqUnion {
                    flags: (IFF_UP | IFF_RUNNING | IFF_BROADCAST | IFF_MULTICAST) as i16,
                };
                Ok(0)
            }

            SIOCGIFADDR => {
                #[allow(unsafe_code)]
                let ifr = unsafe { &mut *(arg1 as *mut IfReq) };
                let ifname = ifreq_name(&ifr.ifr_name)?;
                let iface = iface_by_name(ifname)?;
                let addr = iface_ipv4_cidr(&*iface)
                    .map(|cidr| ipv4_sockaddr(cidr.address()))
                    .unwrap_or_else(|| ipv4_sockaddr(Ipv4Address::UNSPECIFIED));
                ifr.ifr_ifru = IfReqUnion { addr };
                Ok(0)
            }

            SIOCSIFADDR => {
                #[allow(unsafe_code)]
                let ifr = unsafe { &*(arg1 as *const IfReq) };
                let ifname = ifreq_name(&ifr.ifr_name)?;
                let iface = iface_by_name(ifname)?;
                #[allow(unsafe_code)]
                let addr = unsafe { Ipv4Address::from_bytes(&ifr.ifr_ifru.addr.sin_addr.to_ne_bytes()) };
                let prefix_len = iface_ipv4_cidr(&*iface)
                    .map(|cidr| cidr.prefix_len())
                    .unwrap_or(32);
                iface
                    .set_ipv4_address(Ipv4Cidr::new(addr, prefix_len))
                    .map_err(|_| LxError::EINVAL)?;
                Ok(0)
            }

            SIOCGIFNETMASK => {
                #[allow(unsafe_code)]
                let ifr = unsafe { &mut *(arg1 as *mut IfReq) };
                let ifname = ifreq_name(&ifr.ifr_name)?;
                let iface = iface_by_name(ifname)?;
                let addr = iface_ipv4_cidr(&*iface)
                    .map(|cidr| ipv4_sockaddr(ipv4_netmask(cidr.prefix_len())))
                    .unwrap_or_else(|| ipv4_sockaddr(Ipv4Address::UNSPECIFIED));
                ifr.ifr_ifru = IfReqUnion { addr };
                Ok(0)
            }

            SIOCSIFNETMASK => {
                #[allow(unsafe_code)]
                let ifr = unsafe { &*(arg1 as *const IfReq) };
                let ifname = ifreq_name(&ifr.ifr_name)?;
                let iface = iface_by_name(ifname)?;
                #[allow(unsafe_code)]
                let netmask =
                    unsafe { Ipv4Address::from_bytes(&ifr.ifr_ifru.addr.sin_addr.to_ne_bytes()) };
                let prefix_len = prefix_len_from_netmask(netmask)?;
                let addr = iface_ipv4_cidr(&*iface)
                    .map(|cidr| cidr.address())
                    .unwrap_or(Ipv4Address::UNSPECIFIED);
                iface
                    .set_ipv4_address(Ipv4Cidr::new(addr, prefix_len))
                    .map_err(|_| LxError::EINVAL)?;
                Ok(0)
            }

            // SIOCGIFHWADDR: get hardware address
            SIOCGIFHWADDR => {
                #[allow(unsafe_code)]
                let ifr = unsafe { &mut *(arg1 as *mut IfReq) };
                let ifname = ifreq_name(&ifr.ifr_name)?;
                let ifaces = kernel_hal::drivers::all_net();
                for iface in ifaces.as_vec().iter() {
                    if iface.get_ifname() == ifname {
                        let mac = iface.get_mac();
                        unsafe {
                            ifr.ifr_ifru.hwaddr.sa_family = ARPHRD_ETHER;
                            ifr.ifr_ifru.hwaddr.sa_data[..6].copy_from_slice(mac.as_bytes());
                        }
                        return Ok(0);
                    }
                }
                error!("  NOT FOUND!");
                Err(LxError::ENODEV)
            }


            // SIOCGIFMTU: get MTU
            SIOCGIFMTU => {
                #[allow(unsafe_code)]
                let ifr = unsafe { &mut *(arg1 as *mut IfReq) };
                ifr.ifr_ifru = IfReqUnion { ifmtu: 1500 };
                Ok(0)
            }

            // SIOCGIFMETRIC: get metric
            SIOCGIFMETRIC => {
                #[allow(unsafe_code)]
                let ifr = unsafe { &mut *(arg1 as *mut IfReq) };
                ifr.ifr_ifru = IfReqUnion { ifmetric: 0 };
                Ok(0)
            }

            // SIOCGARP
            SIOCGARP => {
                // TODO: check addr
                #[allow(unsafe_code)]
                let req = unsafe { &mut *(arg1 as *mut ArpReq) };
                if let AddressFamily::Internet = AddressFamily::from(req.arp_pa.family) {
                    let name = req.arp_dev.as_ptr();
                    #[allow(unsafe_code)]
                    let _ifname = unsafe { from_cstr(name) };
                    let addr = &req.arp_pa as *const SockAddrPlaceholder as *const SockAddr;
                    #[allow(unsafe_code)]
                    let _addr = unsafe {
                        IpAddress::from(Ipv4Address::from_bytes(
                            &u32::from_be((*addr).addr_in.sin_addr).to_be_bytes()[..],
                        ))
                    };
                    // for iface in get_net_device().iter() {
                    //     if iface.get_ifname() == ifname {
                    //         debug!("get arp matched ifname {}", ifname);
                    //         return match iface.get_arp(addr) {
                    //             Some(mac) => {
                    //                 // TODO: update flags
                    //                 req.arp_ha.data[0..6].copy_from_slice(mac.as_bytes());
                    //                 Ok(0)
                    //             }
                    //             None => Err(LxError::ENOENT),
                    //         };
                    //     }
                    // }
                    Err(LxError::ENOENT)
                } else {
                    Err(LxError::EINVAL)
                }
            }
            _ => Ok(0),
        }
    }

    fn get_buffer_capacity(&self) -> Option<(usize, usize)> {
        let sockets = get_sockets();
        let mut set = sockets.lock();
        let socket = set.get::<UdpSocket>(self.inner.lock().handle.0);
        let (recv_ca, send_ca) = (
            socket.payload_recv_capacity(),
            socket.payload_send_capacity(),
        );
        Some((recv_ca, send_ca))
    }

    fn socket_type(&self) -> Option<SocketType> {
        Some(SocketType::SOCK_DGRAM)
    }
}

impl_kobject!(UdpSocketState);

#[async_trait]
impl FileLike for UdpSocketState {
    fn flags(&self) -> OpenFlags {
        self.inner.lock().flags
    }

    fn set_flags(&self, f: OpenFlags) -> LxResult {
        let flags = &mut self.inner.lock().flags;

        // See fcntl, only O_APPEND, O_ASYNC, O_DIRECT, O_NOATIME, O_NONBLOCK
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

    fn dup(&self) -> Arc<dyn FileLike> {
        Arc::new(Self {
            base: KObjectBase::new(),
            inner: self.inner.clone(),
        })
    }

    fn as_socket(&self) -> LxResult<&dyn Socket> {
        Ok(self)
    }
}
