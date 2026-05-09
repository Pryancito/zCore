// udpsocket

use super::socket_address::*;
use crate::fs::{OpenFlags, PollEvents, PollStatus};
use crate::{
    error::{LxError, LxResult},
    fs::FileLike,
    net::{AddressFamily, Endpoint, SockAddr, Socket, SysResult},
};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use async_trait::async_trait;
use bitflags::bitflags;
use core::{mem::size_of, slice};
use kernel_hal::{net::get_net_device, user::*};
use kernel_hal::thread;
use lock::Mutex;

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

// Linux ARPHRD_* hardware type constants
const ARPHRD_ETHER: u16 = 1;

// Linux IFF_* interface flag constants
const IFF_UP: u32 = 0x1;
const IFF_BROADCAST: u32 = 0x2;
const IFF_RUNNING: u32 = 0x40;
const IFF_LOWER_UP: u32 = 0x1_0000;
// Mask meaning "all flags may change" used in ifi_change responses
const IFF_CHANGE_ALL: u32 = 0xFFFF_FFFF;

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
                    Some(buffer.remove(0))
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
        let mut buffer = self.data.lock();
        buffer.clear();
        match message_type {
            NetlinkMessageType::GetLink => {
                let ifaces = get_net_device();
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
        Some(Endpoint::Netlink(NetlinkEndpoint::new(0, 0)))
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

#[repr(C)]
#[derive(Debug)]
pub struct MsgHdr {
    pub msg_name: UserInOutPtr<SockAddr>,
    pub msg_namelen: u32,
    pub msg_iov: UserInPtr<IoVecOut>,
    pub msg_iovlen: usize,
    pub msg_control: usize,
    pub msg_controllen: usize,
    pub msg_flags: usize,
}

impl MsgHdr {
    pub fn set_msg_name_len(&mut self, len: u32) {
        self.msg_namelen = len;
    }
}
