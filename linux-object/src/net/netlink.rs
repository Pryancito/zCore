// udpsocket

use super::socket_address::*;
use crate::fs::{OpenFlags, PollEvents, PollStatus};
use crate::{
    error::{LxError, LxResult},
    fs::FileLike,
    net::{
        AddressFamily, Endpoint, Socket, SysResult, ARPHRD_ETHER, IFF_BROADCAST, IFF_CHANGE_ALL,
        IFF_LOWER_UP, IFF_RUNNING, IFF_UP,
    },
};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use async_trait::async_trait;
use bitflags::bitflags;
use core::{mem::size_of, slice};
use kernel_hal::net::get_net_device;
use kernel_hal::thread;
use lock::Mutex;
use smoltcp::wire::IpCidr;

// Needed by `impl_kobject!`
#[allow(unused_imports)]
use zircon_object::object::*;

pub struct NetlinkSocketState {
    base: zircon_object::object::KObjectBase,
    data: Arc<Mutex<Vec<Vec<u8>>>>,
    _local_endpoint: Option<NetlinkEndpoint>,
    flags: Arc<Mutex<OpenFlags>>,
}

impl Default for NetlinkSocketState {
    fn default() -> Self {
        Self {
            base: zircon_object::object::KObjectBase::new(),
            data: Arc::new(Mutex::new(Vec::new())),
            _local_endpoint: Some(NetlinkEndpoint::new(0, 0)),
            flags: Arc::new(Mutex::new(OpenFlags::RDWR)),
        }
    }
}
impl NetlinkSocketState {}



#[async_trait]
impl Socket for NetlinkSocketState {
    /// missing documentation
    async fn read(&self, data: &mut [u8]) -> (LxResult<usize>, Endpoint) {
        let endpoint = Endpoint::Netlink(NetlinkEndpoint::new(0, 0));
        let non_block = self.flags.lock().contains(OpenFlags::NON_BLOCK);

        loop {
            let maybe_msg = {
                let mut buffer = self.data.lock();
                if buffer.is_empty() {
                    None
                } else {
                    let msg = buffer.remove(0);
                    info!("[netlink] read: type={}, len={}", u16::from_le_bytes([msg[4], msg[5]]), msg.len());
                    Some(msg)
                }
            };

            match maybe_msg {
                Some(msg) => {
                    let n = core::cmp::min(msg.len(), data.len());
                    if n != 0 {
                        data[..n].copy_from_slice(&msg[..n]);
                    }
                    return (Ok(n), endpoint);
                }
                None if non_block => return (Err(LxError::EAGAIN), endpoint),
                None => thread::yield_now().await,
            }
        }
    }

    fn write(&self, data: &[u8], _sendto_endpoint: Option<Endpoint>) -> SysResult {
        if data.len() < size_of::<NetlinkMessageHeader>() {
            return Err(LxError::EINVAL);
        }
        #[allow(unsafe_code)]
        let header = unsafe { &*(data.as_ptr() as *const NetlinkMessageHeader) };
        if header.nlmsg_len as usize > data.len() {
            return Err(LxError::EINVAL);
        }
        let message_type = NetlinkMessageType::from(header.nlmsg_type);
        info!("Netlink write: message_type={:?}, len={}, seq={}", message_type, header.nlmsg_len, header.nlmsg_seq);
        let mut buffer = self.data.lock();
        buffer.clear();
        match message_type {
            NetlinkMessageType::GetLink => {
                let ifaces = get_net_device();
                info!("Netlink GetLink: found {} interfaces", ifaces.len());
                for (i, iface) in ifaces.iter().enumerate() {
                    let mut msg = Vec::new();
                    let new_header = NetlinkMessageHeader {
                        nlmsg_len: 0, // to be determined later
                        nlmsg_type: NetlinkMessageType::NewLink.into(),
                        nlmsg_flags: NetlinkMessageFlags::MULTI,
                        nlmsg_seq: header.nlmsg_seq,
                        nlmsg_pid: 0, // kernel responses use pid 0
                    };
                    msg.push_ext(new_header);

                    let if_info = IfaceInfoMsg {
                        ifi_family: (u16::from(AddressFamily::Unspecified)) as u8,
                        ifi_pad: 0,
                        ifi_type: ARPHRD_ETHER,
                        ifi_index: (i as i32) + 1, // Linux interface indices start at 1
                        ifi_flags: IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_LOWER_UP,
                        ifi_change: IFF_CHANGE_ALL, // all flags changeable (kernel convention)
                    };
                    msg.align4();
                    msg.push_ext(if_info);

                    let mut attrs = Vec::new();

                    let mac_addr = iface.get_mac();
                    push_rtattr_bytes(
                        &mut attrs,
                        RouteAttrTypes::Address.into(),
                        mac_addr.as_bytes(),
                    );

                    // Broadcast MAC for Ethernet.
                    push_rtattr_bytes(
                        &mut attrs,
                        RouteAttrTypes::Broadcast.into(),
                        &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                    );

                    // MTU (best-effort default; drivers can expose real value later).
                    push_rtattr_u32(&mut attrs, RouteAttrTypes::MTU.into(), 1500);

                    // ifOperStatus: 6 == IF_OPER_UP.
                    push_rtattr_bytes(&mut attrs, RouteAttrTypes::OperState.into(), &[6u8]);

                    // IFLA_LINK: for plain Ethernet, point to self ifindex.
                    push_rtattr_u32(
                        &mut attrs,
                        RouteAttrTypes::Link.into(),
                        (i as u32) + 1,
                    );

                    let ifname = iface.get_ifname();
                    // IFLA_IFNAME includes a null terminator (Linux kernel convention)
                    let mut ifname_bytes = Vec::from(ifname.as_bytes());
                    ifname_bytes.push(0u8);
                    push_rtattr_bytes(
                        &mut attrs,
                        RouteAttrTypes::Ifname.into(),
                        &ifname_bytes,
                    );

                    msg.align4();
                    msg.append(&mut attrs);

                    msg.align4();
                    msg.set_ext(0, msg.len() as u32);

                    buffer.push(msg);
                }
            }
            NetlinkMessageType::GetAddr => {
                let ifaces = get_net_device();
                for (i, iface) in ifaces.iter().enumerate() {
                    let ip_addrs = iface.get_ip_address();

                    // for j in 0..ip_addrs.len() {
                    for ip in &ip_addrs {
                        let mut msg = Vec::new();
                        let new_header = NetlinkMessageHeader {
                            nlmsg_len: 0, // to be determined later
                            nlmsg_type: NetlinkMessageType::NewAddr.into(),
                            nlmsg_flags: NetlinkMessageFlags::MULTI,
                            nlmsg_seq: header.nlmsg_seq,
                            nlmsg_pid: 0, // kernel responses use pid 0
                        };
                        msg.push_ext(new_header);

                        let family: u16 = AddressFamily::Internet.into();
                        let if_addr = IfaceAddrMsg {
                            ifa_family: family as u8,
                            ifa_prefixlen: ip.prefix_len(),
                            ifa_flags: 0,
                            ifa_scope: 0,
                            ifa_index: (i + 1) as u32, // must match GetLink ifi_index (1-based)
                        };
                        msg.align4();
                        msg.push_ext(if_addr);

                        let mut attrs = Vec::new();

                        let ip_addr = ip.address();
                        // IFA_LOCAL and IFA_ADDRESS are both used by userland.
                        push_rtattr_bytes(
                            &mut attrs,
                            IfAddrAttrTypes::Local.into(),
                            ip_addr.as_bytes(),
                        );
                        push_rtattr_bytes(
                            &mut attrs,
                            IfAddrAttrTypes::Address.into(),
                            ip_addr.as_bytes(),
                        );

                        // Label (interface name) with NUL terminator.
                        let ifname = iface.get_ifname();
                        let mut ifname_bytes = Vec::from(ifname.as_bytes());
                        ifname_bytes.push(0u8);
                        push_rtattr_bytes(
                            &mut attrs,
                            IfAddrAttrTypes::Label.into(),
                            &ifname_bytes,
                        );

                        // IPv4 broadcast if applicable.
                        if ip_addr.as_bytes().len() == 4 {
                            let bcast = ipv4_broadcast(
                                smoltcp::wire::Ipv4Address::from_bytes(ip_addr.as_bytes()),
                                ip.prefix_len(),
                            );
                            push_rtattr_bytes(
                                &mut attrs,
                                IfAddrAttrTypes::Broadcast.into(),
                                bcast.as_bytes(),
                            );
                        }

                        msg.align4();
                        msg.append(&mut attrs);

                        msg.align4();
                        msg.set_ext(0, msg.len() as u32);

                        buffer.push(msg);
                    }
                }
            }
            NetlinkMessageType::NewAddr => {
                // RTM_NEWADDR: configure an IP address on an interface.
                // Payload: IfaceAddrMsg + IFA_* attributes.
                use kernel_hal::net::get_net_device;
                if data.len() < size_of::<NetlinkMessageHeader>() + size_of::<IfaceAddrMsg>() {
                    return Err(LxError::EINVAL);
                }
                let ifa_off = size_of::<NetlinkMessageHeader>();
                #[allow(unsafe_code)]
                let ifa = unsafe { &*(data[ifa_off..].as_ptr() as *const IfaceAddrMsg) };

                // Walk attributes to find IFA_LOCAL / IFA_ADDRESS
                let attrs_off = ifa_off + size_of::<IfaceAddrMsg>();
                let mut ip_bytes: Option<[u8; 4]> = None;
                let mut ptr = attrs_off;
                while ptr + size_of::<RouteAttr>() <= data.len() {
                    #[allow(unsafe_code)]
                    let rta = unsafe { &*(data[ptr..].as_ptr() as *const RouteAttr) };
                    let rta_len = rta.rta_len as usize;
                    if rta_len < size_of::<RouteAttr>() { break; }
                    let payload = &data[ptr + size_of::<RouteAttr>()..ptr + rta_len];
                    let t = IfAddrAttrTypes::from(rta.rta_type);
                    if matches!(t, IfAddrAttrTypes::Local | IfAddrAttrTypes::Address) {
                        if payload.len() == 4 {
                            let mut arr = [0u8; 4];
                            arr.copy_from_slice(payload);
                            ip_bytes = Some(arr);
                        }
                    }
                    // rtattr entries are aligned to 4 bytes
                    ptr += (rta_len + 3) & !3;
                }
                if let Some(bytes) = ip_bytes {
                    let cidr = smoltcp::wire::Ipv4Cidr::new(
                        smoltcp::wire::Ipv4Address::from_bytes(&bytes),
                        ifa.ifa_prefixlen,
                    );
                    let iface_idx = (ifa.ifa_index as usize).saturating_sub(1);
                    let ifaces = get_net_device();
                    if let Some(iface) = ifaces.get(iface_idx) {
                        let _ = iface.set_ipv4_address(cidr);
                        info!("[netlink] NewAddr: set {}.{}.{}.{}/{} on if{}", bytes[0], bytes[1], bytes[2], bytes[3], ifa.ifa_prefixlen, iface_idx);
                    }
                }
                // ACK (error=0)
                push_ack(&mut buffer, header.nlmsg_seq);
            }
            NetlinkMessageType::NewRoute => {
                // RTM_NEWROUTE: add a routing entry (default gateway etc.)
                // Payload: rtmsg + RTA_GATEWAY attribute.
                use kernel_hal::net::get_net_device;
                use smoltcp::wire::IpAddress;
                // RTA_GATEWAY = 5
                const RTA_GATEWAY: u16 = 5;
                let rtm_off = size_of::<NetlinkMessageHeader>();
                // rtmsg is 12 bytes (af, dst_len, src_len, tos, table, proto, scope, type_, flags)
                const RTM_SIZE: usize = 12;
                if data.len() < rtm_off + RTM_SIZE {
                    return Err(LxError::EINVAL);
                }
                let mut gw_bytes: Option<[u8; 4]> = None;
                let mut ifindex: usize = 0;
                let mut ptr = rtm_off + RTM_SIZE;
                // RTA_OIF = 4
                const RTA_OIF: u16 = 4;
                while ptr + size_of::<RouteAttr>() <= data.len() {
                    #[allow(unsafe_code)]
                    let rta = unsafe { &*(data[ptr..].as_ptr() as *const RouteAttr) };
                    let rta_len = rta.rta_len as usize;
                    if rta_len < size_of::<RouteAttr>() { break; }
                    let payload = &data[ptr + size_of::<RouteAttr>()..ptr + rta_len];
                    if rta.rta_type == RTA_GATEWAY && payload.len() == 4 {
                        let mut arr = [0u8; 4];
                        arr.copy_from_slice(payload);
                        gw_bytes = Some(arr);
                    } else if rta.rta_type == RTA_OIF && payload.len() == 4 {
                        #[allow(unsafe_code)]
                        let idx = unsafe { *(payload.as_ptr() as *const u32) } as usize;
                        ifindex = idx.saturating_sub(1);
                    }
                    ptr += (rta_len + 3) & !3;
                }
                if let Some(gw) = gw_bytes {
                    let ifaces = get_net_device();
                    if let Some(iface) = ifaces.get(ifindex) {
                        let gw_addr = IpAddress::Ipv4(smoltcp::wire::Ipv4Address::from_bytes(&gw));
                        let _ = iface.add_route(IpCidr::new(IpAddress::v4(0, 0, 0, 0), 0), Some(gw_addr));
                        info!("[netlink] NewRoute: default gw {}.{}.{}.{}", gw[0], gw[1], gw[2], gw[3]);
                    }
                }
                // ACK
                push_ack(&mut buffer, header.nlmsg_seq);
            }
            NetlinkMessageType::GetRoute => {
                // RTM_GETROUTE: dump the routing table.
                // We currently have no way to enumerate smoltcp routes, so we
                // return an empty table.  Many DHCP clients treat this as "no existing
                // routes to remove before adding ours", which is safe.
                // The NLMSG_DONE sentinel is appended after the match block.
                info!("[netlink] GetRoute: returning empty routing table");
            }
            NetlinkMessageType::DelAddr => {
                // RTM_DELADDR: remove an IP address from an interface.
                // Return a success ACK; the actual address removal is not
                // implemented yet (clients treat a non-fatal error gracefully,
                // but a clean ACK avoids unnecessary log noise).
                info!("[netlink] DelAddr: ACK (address removal not yet implemented)");
                push_ack(&mut buffer, header.nlmsg_seq);
            }
            NetlinkMessageType::DelRoute => {
                // RTM_DELROUTE: remove a routing entry.
                // Return a success ACK; same rationale as DelAddr above.
                info!("[netlink] DelRoute: ACK (route removal not yet implemented)");
                push_ack(&mut buffer, header.nlmsg_seq);
            }
            _ => {
                // Unknown/unimplemented request: return NLMSG_ERROR with -EOPNOTSUPP.
                // This is better than a silent NLMSG_DONE which confuses userland.
                const EOPNOTSUPP: i32 = 95;
                #[repr(C)]
                #[derive(Copy, Clone)]
                struct NetlinkError {
                    error: i32,
                    msg: NetlinkMessageHeader,
                }
                const _: () = {
                    assert!(size_of::<NetlinkError>() == 20);
                };
                let err = NetlinkError {
                    error: -EOPNOTSUPP,
                    msg: *header,
                };
                let mut msg = Vec::new();
                let new_header = NetlinkMessageHeader {
                    nlmsg_len: 0,
                    nlmsg_type: NetlinkMessageType::Error.into(),
                    nlmsg_flags: NetlinkMessageFlags::MULTI,
                    nlmsg_seq: header.nlmsg_seq,
                    nlmsg_pid: 0,
                };
                msg.push_ext(new_header);
                msg.align4();
                msg.push_ext(err);
                msg.align4();
                msg.set_ext(0, msg.len() as u32);
                buffer.push(msg);
            }
        }
        let mut msg = Vec::new();
        let new_header = NetlinkMessageHeader {
            nlmsg_len: 0, // to be determined later
            nlmsg_type: NetlinkMessageType::Done.into(),
            nlmsg_flags: NetlinkMessageFlags::MULTI,
            nlmsg_seq: header.nlmsg_seq,
            nlmsg_pid: 0, // kernel responses use pid 0
        };
        msg.push_ext(new_header);
        msg.align4();
        msg.set_ext(0, msg.len() as u32);
        buffer.push(msg);
        self.base.signal_set(Signal::READABLE);
        info!("[netlink] write: pushed DONE, buffer len now {}", buffer.len());
        Ok(data.len())
    }

    /// connect
    async fn connect(&self, _endpoint: Endpoint) -> SysResult {
        unimplemented!()
    }

    fn bind(&self, _endpoint: Endpoint) -> SysResult {
        warn!("bind netlink socket");
        // if let Endpoint::Netlink(mut net_link) = endpoint {
        //     if net_link.port_id == 0 {
        //         net_link.port_id = get_ephemeral_port();
        //     }
        //     self.local_endpoint = Some(ip);
        //     self.is_listening = false;
        //     Ok(0)
        // } else {
        //     Err(LxError::EINVAL)
        // }
        Ok(0)
    }

    fn listen(&self) -> SysResult {
        unimplemented!()
    }

    fn shutdown(&self) -> SysResult {
        unimplemented!()
    }

    async fn accept(&self) -> LxResult<(Arc<dyn FileLike>, Endpoint)> {
        unimplemented!()
    }

    fn endpoint(&self) -> Option<Endpoint> {
        // Use the kernel-object ID as nl_pid so that each socket gets a
        // unique, non-zero identifier.  This is important because some clients
        // stores the route_fd's nl_pid as `priv->route_pid` and then
        // filters out netlink messages whose nlmsg_pid equals route_pid.
        // If nl_pid were 0 (the kernel's pid), every kernel reply would
        // be silently dropped.
        //
        // We reduce the 64-bit koid into the u32 space with a modulo so
        // that the value is always defined (no wrapping UB).  Collisions
        // can only occur after u32::MAX - 1 simultaneously-alive sockets,
        // which is not a concern in practice.
        let reduced = self.base.id % u32::MAX as u64;
        let nl_pid = (reduced as u32).max(1);
        Some(Endpoint::Netlink(NetlinkEndpoint::new(nl_pid, 0)))
    }

    fn remote_endpoint(&self) -> Option<Endpoint> {
        unimplemented!()
    }

    fn setsockopt(&self, _level: usize, _opt: usize, _data: &[u8]) -> SysResult {
        Ok(0)
    }

    fn ioctl(&self, _request: usize, _arg1: usize, _arg2: usize, _arg3: usize) -> SysResult {
        Ok(0)
    }

    fn poll(&self, _events: PollEvents) -> (bool, bool, bool) {
        let readable = !self.data.lock().is_empty();
        (readable, true, false)
    }
}

zircon_object::impl_kobject!(NetlinkSocketState);

#[async_trait]
impl FileLike for NetlinkSocketState {
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

    fn dup(&self) -> Arc<dyn FileLike> {
        Arc::new(Self {
            base: KObjectBase::new(),
            data: self.data.clone(),
            _local_endpoint: self._local_endpoint.clone(),
            flags: self.flags.clone(),
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

/// Common structure:
/// | nlmsghdr | ifinfomsg/ifaddrmsg | rtattr | rtattr | rtattr | ... | rtattr
/// All aligned to 4 bytes boundary
#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct NetlinkMessageHeader {
    nlmsg_len: u32,                   // length of message including header
    nlmsg_type: u16,                  // message content
    nlmsg_flags: NetlinkMessageFlags, // additional flags
    nlmsg_seq: u32,                   // sequence number
    nlmsg_pid: u32,                   // sending process port id
}

const _: () = {
    // Linux rtnetlink ABI sanity checks (x86_64): nlmsghdr is 16 bytes.
    assert!(size_of::<NetlinkMessageHeader>() == 16);
};

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct IfaceInfoMsg {
    // Matches Linux `struct ifinfomsg` layout.
    ifi_family: u8,
    ifi_pad: u8,
    ifi_type: u16,
    ifi_index: i32,
    ifi_flags: u32,
    ifi_change: u32,
}

const _: () = {
    // Linux `struct ifinfomsg` is 16 bytes.
    assert!(size_of::<IfaceInfoMsg>() == 16);
};

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct IfaceAddrMsg {
    ifa_family: u8,
    ifa_prefixlen: u8,
    ifa_flags: u8,
    ifa_scope: u8,
    ifa_index: u32,
}

const _: () = {
    // Linux `struct ifaddrmsg` is 8 bytes.
    assert!(size_of::<IfaceAddrMsg>() == 8);
};

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct RouteAttr {
    rta_len: u16,
    rta_type: u16,
}

const _: () = {
    // Linux `struct rtattr` is 4 bytes.
    assert!(size_of::<RouteAttr>() == 4);
};

bitflags! {
    struct NetlinkMessageFlags : u16 {
        const REQUEST = 0x01;
        const MULTI = 0x02;
        const ACK = 0x04;
        const ECHO = 0x08;
        const DUMP_INTR = 0x10;
        const DUMP_FILTERED = 0x20;
        // GET request
        const ROOT = 0x100;
        const MATCH = 0x200;
        const ATOMIC = 0x400;
        const DUMP = 0x100 | 0x200;
        // NEW request
        const REPLACE = 0x100;
        const EXCL = 0x200;
        const CREATE = 0x400;
        const APPEND = 0x800;
        // DELETE request
        const NONREC = 0x100;
        // ACK message
        const CAPPED = 0x100;
        const ACK_TLVS = 0x200;
    }
}

enum_with_unknown! {
    /// Netlink message types
    pub doc enum NetlinkMessageType(u16) {
        /// Nothing
        Noop = 1,
        /// Error
        Error = 2,
        /// End of a dump
        Done = 3,
        /// Data lost
        Overrun = 4,
        /// New link
        NewLink = 16,
        /// Delete link
        DelLink = 17,
        /// Get link
        GetLink = 18,
        /// Set link
        SetLink = 19,
        /// New addr
        NewAddr = 20,
        /// Delete addr
        DelAddr = 21,
        /// Get addr
        GetAddr = 22,
        /// New route
        NewRoute = 24,
        /// Delete route
        DelRoute = 25,
        /// Get route
        GetRoute = 26,
    }
}

enum_with_unknown! {
    /// Route Attr Types
    pub doc enum RouteAttrTypes(u16) {
        /// Unspecified
        Unspecified = 0,
        /// MAC Address
        Address = 1,
        /// Broadcast
        Broadcast = 2,
        /// Interface name
        Ifname = 3,
        /// MTU
        MTU = 4,
        /// Link
        Link = 5,
        /// Operational state (IF_OPER_*)
        OperState = 16,
    }
}

enum_with_unknown! {
    /// ifaddrmsg attribute types (IFA_*)
    pub doc enum IfAddrAttrTypes(u16) {
        /// Unspecified
        Unspecified = 0,
        /// IFA_ADDRESS
        Address = 1,
        /// IFA_LOCAL
        Local = 2,
        /// IFA_LABEL
        Label = 3,
        /// IFA_BROADCAST
        Broadcast = 4,
    }
}

fn push_rtattr_bytes(dst: &mut Vec<u8>, rta_type: u16, payload: &[u8]) {
    let attr = RouteAttr {
        rta_len: (payload.len() + size_of::<RouteAttr>()) as u16,
        rta_type,
    };
    dst.align4();
    dst.push_ext(attr);
    dst.extend_from_slice(payload);
}

fn push_rtattr_u32(dst: &mut Vec<u8>, rta_type: u16, v: u32) {
    push_rtattr_bytes(dst, rta_type, &v.to_ne_bytes());
}

/// Build a success ACK (NLMSG_ERROR with error=0) and push it onto `buffer`.
fn push_ack(buffer: &mut Vec<Vec<u8>>, seq: u32) {
    let ack = NetlinkMessageHeader {
        nlmsg_len: (size_of::<NetlinkMessageHeader>() + size_of::<i32>()) as u32,
        nlmsg_type: NetlinkMessageType::Error.into(),
        nlmsg_flags: NetlinkMessageFlags::empty(),
        nlmsg_seq: seq,
        nlmsg_pid: 0,
    };
    let mut msg = Vec::new();
    msg.push_ext(ack);
    msg.push_ext(0i32); // error = 0 means success
    msg.align4();
    msg.set_ext(0, msg.len() as u32);
    info!("[netlink] push_ack: seq={}, len={}", seq, msg.len());
    buffer.push(msg);
}

fn ipv4_broadcast(addr: smoltcp::wire::Ipv4Address, prefix_len: u8) -> smoltcp::wire::Ipv4Address {
    let ip = u32::from_be_bytes(addr.0);
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len as u32)
    };
    let bcast = ip | (!mask);
    smoltcp::wire::Ipv4Address::from_bytes(&bcast.to_be_bytes())
}

trait VecExt {
    fn align4(&mut self);
    fn push_ext<T: Sized>(&mut self, data: T);
    fn set_ext<T: Sized>(&mut self, offset: usize, data: T);
}

impl VecExt for Vec<u8> {
    fn align4(&mut self) {
        let len = (self.len() + 3) & !3;
        if len > self.len() {
            self.resize(len, 0);
        }
    }

    fn push_ext<T: Sized>(&mut self, data: T) {
        #[allow(unsafe_code)]
        let bytes =
            unsafe { slice::from_raw_parts(&data as *const T as *const u8, size_of::<T>()) };
        for byte in bytes {
            self.push(*byte);
        }
    }

    fn set_ext<T: Sized>(&mut self, offset: usize, data: T) {
        if self.len() < offset + size_of::<T>() {
            self.resize(offset + size_of::<T>(), 0);
        }
        #[allow(unsafe_code)]
        let bytes =
            unsafe { slice::from_raw_parts(&data as *const T as *const u8, size_of::<T>()) };
        self[offset..(bytes.len() + offset)].copy_from_slice(bytes);
    }
}


