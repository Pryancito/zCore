//! Linux socket objects
//!

/// missing documentation
#[macro_use]
pub mod socket_address;
use crate::fs::{FileLike, PollEvents};
use crate::error::{LxError, LxResult};
use kernel_hal::user::{IoVecOut, UserInPtr, UserInOutPtr};
use smoltcp::wire::{Ipv4Cidr, IpCidr, IpEndpoint};
pub use socket_address::*;
use log::*;

pub fn ifreq_name(raw: &[u8; 16]) -> LxResult<&str> {
    let len = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    core::str::from_utf8(&raw[..len]).map_err(|_| LxError::EINVAL)
}

/// Global initialization for the network stack.
pub fn init() {
    zcore_drivers::net::set_packet_callback(packet::push_packet);
}

pub fn iface_by_name(ifname: &str) -> LxResult<Arc<dyn zcore_drivers::scheme::NetScheme>> {
    get_net_device()
        .into_iter()
        .find(|iface| iface.get_ifname() == ifname)
        .ok_or(LxError::ENODEV)
}

pub fn iface_ipv4_cidr(iface: &dyn zcore_drivers::scheme::NetScheme) -> Option<Ipv4Cidr> {
    iface
        .get_ip_address()
        .into_iter()
        .find_map(|cidr| match cidr {
            IpCidr::Ipv4(cidr) => Some(cidr),
            _ => None,
        })
}

pub fn ipv4_sockaddr(addr: Ipv4Address) -> SockAddrIn {
    SockAddrIn {
        sin_family: AddressFamily::Internet.into(),
        sin_port: 0,
        sin_addr: u32::from_ne_bytes(addr.0),
        sin_zero: [0; 8],
    }
}

pub fn ipv4_netmask(prefix_len: u8) -> Ipv4Address {
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len as u32)
    };
    Ipv4Address::from_bytes(&mask.to_be_bytes())
}

pub fn ipv4_broadcast(addr: Ipv4Address, prefix_len: u8) -> Ipv4Address {
    let addr_u32 = u32::from_be_bytes(addr.0);
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len as u32)
    };
    let broadcast = addr_u32 | !mask;
    Ipv4Address::from_bytes(&broadcast.to_be_bytes())
}

pub fn prefix_len_from_netmask(addr: Ipv4Address) -> LxResult<u8> {
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


/// missing documentation
pub mod tcp;
pub use tcp::*;

/// missing documentation
pub mod udp;
pub use udp::*;

/// missing documentation
pub mod raw;
pub use raw::*;

/// missing documentation
pub mod packet;
pub use packet::*;

/// missing documentation
pub mod netlink;
pub use netlink::*;
pub mod unix;
pub use unix::*;
pub mod listen_table;
pub use listen_table::*;

/// missing documentation
// pub mod icmp;
// pub use icmp::*;

// pub mod stack;

// ============= Socket Set =============
use zcore_drivers::net::get_sockets;
// lazy_static! {
//     /// Global SocketSet in smoltcp.
//     ///
//     /// Because smoltcp is a single thread network stack,
//     /// every socket operation needs to lock this.
//     pub static ref SOCKETS: Mutex<SocketSet<'static>> =
//         Mutex::new(SocketSet::new(vec![]));
// }

// ============= Socket Set =============

// ============= Define =============

// ========TCP

/// missing documentation
pub const TCP_SENDBUF: usize = 64 * 1024;
/// missing documentation
pub const TCP_RECVBUF: usize = 64 * 1024;

// ========UDP

/// missing documentation
pub const UDP_METADATA_BUF: usize = 256;
/// missing documentation
pub const UDP_SENDBUF: usize = 512 * 1024;
/// missing documentation
pub const UDP_RECVBUF: usize = 512 * 1024;

// ========RAW

/// missing documentation
pub const RAW_METADATA_BUF: usize = 64;
/// missing documentation
pub const RAW_SENDBUF: usize = 64 * 1024; // 64K
/// missing documentation
pub const RAW_RECVBUF: usize = 64 * 1024; // 64K

// ========RAW

/// missing documentation
pub const ICMP_METADATA_BUF: usize = 1024;
/// missing documentation
pub const ICMP_SENDBUF: usize = 64 * 1024; // 64K
/// missing documentation
pub const ICMP_RECVBUF: usize = 64 * 1024; // 64K

// ========Other

/// missing documentation
pub const IPPROTO_IP: usize = 0;
/// missing documentation
pub const IP_HDRINCL: usize = 3;

pub const SOCKET_TYPE_MASK: usize = 0xff;

pub const SOCKET_FD: usize = 1000;
pub const SIOCADDRT: usize = 0x890b;
pub const SIOCDELRT: usize = 0x890c;

pub const SIOCGIFCONF: usize = 0x8912;
pub const SIOCGIFFLAGS: usize = 0x8913;
pub const SIOCSIFFLAGS: usize = 0x8914;
pub const SIOCGIFADDR: usize = 0x8915;
pub const SIOCSIFADDR: usize = 0x8916;
pub const SIOCGIFBRDADDR: usize = 0x8919;
pub const SIOCSIFBRDADDR: usize = 0x891a;
pub const SIOCGIFNETMASK: usize = 0x891b;
pub const SIOCSIFNETMASK: usize = 0x891c;
pub const SIOCGIFMETRIC: usize = 0x891d;
pub const SIOCGIFMTU: usize = 0x8921;
pub const SIOCGIFHWADDR: usize = 0x8927;
pub const SIOCGIFINDEX: usize = 0x8933;
pub const SIOCGARP: usize = 0x8954;
pub const ARPHRD_ETHER: u16 = 1;

pub const IFF_UP: u32 = 0x1;
pub const IFF_BROADCAST: u32 = 0x2;
pub const IFF_DEBUG: u32 = 0x4;
pub const IFF_LOOPBACK: u32 = 0x8;
pub const IFF_POINTOPOINT: u32 = 0x10;
pub const IFF_NOTRAILERS: u32 = 0x20;
pub const IFF_RUNNING: u32 = 0x40;
pub const IFF_NOARP: u32 = 0x80;
pub const IFF_PROMISC: u32 = 0x100;
pub const IFF_ALLMULTI: u32 = 0x200;
pub const IFF_MASTER: u32 = 0x400;
pub const IFF_SLAVE: u32 = 0x800;
pub const IFF_MULTICAST: u32 = 0x1000;
pub const IFF_LOWER_UP: u32 = 0x1_0000;
pub const IFF_CHANGE_ALL: u32 = 0xFFFF_FFFF;


#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockAddrHw {
    pub sa_family: u16,
    pub sa_data: [u8; 14],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union IfReqUnion {
    pub addr: SockAddrIn,
    pub hwaddr: SockAddrHw,
    pub ifindex: i32,
    pub ifmtu: i32,
    pub ifmetric: i32,
    pub flags: i16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IfReq {
    pub ifr_name: [u8; 16],
    pub ifr_ifru: IfReqUnion,
}

impl IfReq {
    pub fn name(&self) -> &str {
        let len = self.ifr_name.iter().position(|&b| b == 0).unwrap_or(self.ifr_name.len());
        core::str::from_utf8(&self.ifr_name[..len]).unwrap_or("")
    }
}

pub const RTF_UP: u16 = 0x0001;
pub const RTF_GATEWAY: u16 = 0x0002;
pub const RTF_HOST: u16 = 0x0004;

#[repr(C)]
pub struct RtEntry {
    pub rt_pad1: usize,
    pub rt_dst: SockAddrIn,
    pub rt_gateway: SockAddrIn,
    pub rt_genmask: SockAddrIn,
    pub rt_flags: u16,
    pub rt_pad2: i16,
    pub rt_pad3: usize,
    pub rt_pad4: usize,
    pub rt_metric: i16,
    pub rt_dev: *mut u8,
    pub rt_mtu: usize,
    pub rt_window: usize,
    pub rt_irtt: u16,
}

#[repr(C)]
pub struct IfConf {
    pub ifc_len: i32,
    pub ifc_buf: usize,
}

use numeric_enum_macro::numeric_enum;

numeric_enum! {
    #[repr(usize)]
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    #[allow(non_camel_case_types)]
    /// Generic musl socket domain.
    pub enum Domain {
    /// Local communication
    AF_UNIX = 1,
        /// IPv4 Internet protocols
        AF_INET = 2,
        /// IPv6 Internet protocols
        AF_INET6 = 10,
        /// Kernel user interface device
        AF_NETLINK = 16,
    /// Low-level packet interface
    AF_PACKET = 17,
    }
}

numeric_enum! {
    #[repr(usize)]
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    #[allow(non_camel_case_types)]
    /// Generic musl socket type.
    pub enum SocketType {
        /// Provides sequenced, reliable, two-way, connection-based byte streams.
        /// An out-of-band data transmission mechanism may be supported.
        SOCK_STREAM = 1,
        /// Supports datagrams (connectionless, unreliable messages of a fixed maximum length).
        SOCK_DGRAM = 2,
        /// Provides raw network protocol access.
        SOCK_RAW = 3,
        /// Provides a reliable datagram layer that does not guarantee ordering.
        SOCK_RDM = 4,
        /// Provides a sequenced, reliable, two-way connection-based data
        /// transmission path for datagrams of fixed maximum length;
        /// a consumer is required to read an entire packet with each input system call.
        SOCK_SEQPACKET = 5,
        /// Datagram Congestion Control Protocol socket
        SOCK_DCCP = 6,
        /// Obsolete and should not be used in new programs.
        SOCK_PACKET = 10,
        /// Set O_NONBLOCK flag on the open fd
        SOCK_NONBLOCK = 0x800,
        /// Set FD_CLOEXEC flag on the new fd
        SOCK_CLOEXEC = 0x80000,
    }
}

numeric_enum! {
    #[repr(usize)]
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    #[allow(non_camel_case_types)]
    // define in include/uapi/linux/in.h
    /// Generic musl socket protocol.
    pub enum Protocol {
        /// Dummy protocol for TCP
        IPPROTO_IP = 0,
        /// Internet Control Message Protocol
        IPPROTO_ICMP = 1,
        /// Transmission Control Protocol
        IPPROTO_TCP = 6,
        /// User Datagram Protocol
        IPPROTO_UDP = 17,
        /// IPv6-in-IPv4 tunnelling
        IPPROTO_IPV6 = 41,
        /// ICMPv6
        IPPROTO_ICMPV6 = 58,
    }
}

numeric_enum! {
    #[repr(usize)]
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    #[allow(non_camel_case_types)]
    /// Generic musl socket level.
    pub enum Level {
        /// ipproto ip
        IPPROTO_IP = 0,
        /// sol socket
        SOL_SOCKET = 1,
        /// ipproto tcp
        IPPROTO_TCP = 6,
    }
}

#[repr(C)]
pub struct MsgHdr {
    pub msg_name: UserInOutPtr<SockAddr>,
    pub msg_namelen: u32,
    _pad1: u32,
    pub msg_iov: UserInPtr<IoVecOut>,
    pub msg_iovlen: usize,
    pub msg_control: UserInOutPtr<u8>,
    pub msg_controllen: usize,
    pub msg_flags: i32,
    _pad2: i32,
}

impl MsgHdr {
    pub fn set_msg_name_len(&mut self, len: u32) {
        self.msg_namelen = len;
    }
}


numeric_enum! {
    #[repr(usize)]
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    /// Generic musl socket optname.
    pub enum SolOptname {
        /// reuseaddr
        REUSEADDR = 2,
        /// error
        ERROR = 4,
        /// sndbuf
        SNDBUF = 7,  // 获取发送缓冲区长度
        /// rcvbuf
        RCVBUF = 8,  // 获取接收缓冲区长度
        /// linger
        LINGER = 13,
    }
}

numeric_enum! {
    #[repr(usize)]
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    /// Generic musl socket optname.
    pub enum TcpOptname {
        /// congestion
        CONGESTION = 13,
    }
}

numeric_enum! {
    #[repr(usize)]
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    /// Generic musl socket optname.
    pub enum IpOptname {
        /// hdrincl
        HDRINCL = 3,
    }
}

// ============= Define =============

// ============= SocketHandle =============

use smoltcp::socket::SocketHandle;

/// A wrapper for `SocketHandle`.
/// Auto increase and decrease reference count on Clone and Drop.
#[derive(Debug)]
struct GlobalSocketHandle(SocketHandle);

impl Clone for GlobalSocketHandle {
    fn clone(&self) -> Self {
        get_sockets().lock().retain(self.0);
        Self(self.0)
    }
}

impl Drop for GlobalSocketHandle {
    fn drop(&mut self) {
        let net_sockets = get_sockets();
        let mut sockets = net_sockets.lock();
        sockets.release(self.0);
        sockets.prune();

        // send FIN immediately when applicable
        drop(sockets);
        poll_ifaces();
    }
}

use kernel_hal::net::get_net_device;

/// miss doc
pub fn poll_ifaces() {
    for iface in get_net_device().iter() {
        match iface.poll() {
            Ok(_) => {}
            Err(e) => {
                warn!("error : {:?}", e)
            }
        }
    }
}

// ============= SocketHandle =============

// ============= Rand Port =============

/// !!!! need riscv rng
pub fn rand() -> u64 {
    // use core::arch::x86_64::_rdtsc;
    // rdrand is not implemented in QEMU
    // so use rdtsc instead
    10000
}

#[allow(unsafe_code)]
/// missing documentation
fn get_ephemeral_port() -> u16 {
    // TODO selects non-conflict high port
    static mut EPHEMERAL_PORT: u16 = 0;
    unsafe {
        if EPHEMERAL_PORT == 0 {
            EPHEMERAL_PORT = (49152 + rand() % (65536 - 49152)) as u16;
        }
        if EPHEMERAL_PORT == 65535 {
            EPHEMERAL_PORT = 49152;
        } else {
            EPHEMERAL_PORT += 1;
        }
        EPHEMERAL_PORT
    }
}

// ============= Rand Port =============
// ============= IOCTL =============

pub fn handle_net_ioctl(request: usize, arg1: usize, _arg2: usize, _arg3: usize) -> LxResult<usize> {
    match request {
        // SIOCGIFCONF: get list of interfaces
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
            let out = unsafe { core::slice::from_raw_parts_mut(ifc.ifc_buf as *mut u8, buf_bytes) };
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

        SIOCSIFFLAGS => {
            // Ignore for now, just return success
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

        SIOCGIFBRDADDR => {
            #[allow(unsafe_code)]
            let ifr = unsafe { &mut *(arg1 as *mut IfReq) };
            let ifname = ifreq_name(&ifr.ifr_name)?;
            let iface = iface_by_name(ifname)?;
            let addr = iface_ipv4_cidr(&*iface)
                .map(|cidr| ipv4_sockaddr(ipv4_broadcast(cidr.address(), cidr.prefix_len())))
                .unwrap_or_else(|| ipv4_sockaddr(Ipv4Address::UNSPECIFIED));
            ifr.ifr_ifru = IfReqUnion { addr };
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

        // SIOCADDRT: add route
        SIOCADDRT => {
            #[allow(unsafe_code)]
            let rt = unsafe { &*(arg1 as *const RtEntry) };
            let gateway = if (rt.rt_flags & RTF_GATEWAY) != 0 {
                let addr = Ipv4Address::from_bytes(&rt.rt_gateway.sin_addr.to_ne_bytes());
                Some(IpAddress::Ipv4(addr))
            } else {
                None
            };
            let dst_addr = Ipv4Address::from_bytes(&rt.rt_dst.sin_addr.to_ne_bytes());
            let genmask = Ipv4Address::from_bytes(&rt.rt_genmask.sin_addr.to_ne_bytes());
            let prefix_len = prefix_len_from_netmask(genmask).unwrap_or(0);
            let cidr = IpCidr::Ipv4(Ipv4Cidr::new(dst_addr, prefix_len));

            let ifname = if !rt.rt_dev.is_null() {
                #[allow(unsafe_code)]
                unsafe { from_cstr(rt.rt_dev) }
            } else {
                "eth0" // default to eth0 if not specified
            };

            info!("SIOCADDRT: cidr={:?}, gateway={:?}, dev={}", cidr, gateway, ifname);
            let iface = iface_by_name(ifname)?;
            iface.add_route(cidr, gateway).map_err(|_| LxError::EIO)?;
            Ok(0)
        }

        // SIOCDELRT: delete route
        SIOCDELRT => {
            #[allow(unsafe_code)]
            let rt = unsafe { &*(arg1 as *const RtEntry) };
            let gateway = if (rt.rt_flags & RTF_GATEWAY) != 0 {
                let addr = Ipv4Address::from_bytes(&rt.rt_gateway.sin_addr.to_ne_bytes());
                Some(IpAddress::Ipv4(addr))
            } else {
                None
            };
            let dst_addr = Ipv4Address::from_bytes(&rt.rt_dst.sin_addr.to_ne_bytes());
            let genmask = Ipv4Address::from_bytes(&rt.rt_genmask.sin_addr.to_ne_bytes());
            let prefix_len = prefix_len_from_netmask(genmask).unwrap_or(0);
            let cidr = IpCidr::Ipv4(Ipv4Cidr::new(dst_addr, prefix_len));

            let ifname = if !rt.rt_dev.is_null() {
                #[allow(unsafe_code)]
                unsafe { from_cstr(rt.rt_dev) }
            } else {
                "eth0" // default to eth0 if not specified
            };

            info!("SIOCDELRT: cidr={:?}, gateway={:?}, dev={}", cidr, gateway, ifname);
            let iface = iface_by_name(ifname)?;
            iface.del_route(cidr, gateway).map_err(|_| LxError::EIO)?;
            Ok(0)
        }

        // SIOCGARP
        SIOCGARP => {
            Err(LxError::ENOENT)
        }

        _ => Err(LxError::ENOSYS),
    }
}

// ============= IOCTL =============
// ============= Rand Port =============

// ============= Util =============

#[allow(unsafe_code)]
/// # Safety
/// Convert C string to Rust string
pub unsafe fn from_cstr(s: *const u8) -> &'static str {
    use core::{slice, str};
    let len = (0usize..).find(|&i| *s.add(i) == 0).unwrap();
    str::from_utf8(slice::from_raw_parts(s, len)).unwrap()
}

// ============= Util =============

use crate::error::*;
use alloc::boxed::Box;
use alloc::fmt::Debug;
use alloc::sync::Arc;
use async_trait::async_trait;
// use core::ops::{Deref, DerefMut};
/// Common methods that a socket must have
#[async_trait]
pub trait Socket: Send + Sync + Debug + downcast_rs::DowncastSync {
    /// missing documentation
    async fn read(&self, data: &mut [u8]) -> (SysResult, Endpoint);
    /// missing documentation
    fn write(&self, data: &[u8], sendto_endpoint: Option<Endpoint>) -> SysResult;
    /// wait for some event (in, out, err) on a fd
    fn poll(&self, _events: PollEvents) -> (bool, bool, bool) {
        unimplemented!()
    }
    /// missing documentation
    async fn connect(&self, endpoint: Endpoint) -> SysResult;
    /// missing documentation
    fn bind(&self, _endpoint: Endpoint) -> SysResult {
        Err(LxError::EINVAL)
    }
    /// missing documentation
    fn listen(&self) -> SysResult {
        Err(LxError::EINVAL)
    }
    /// missing documentation
    fn shutdown(&self) -> SysResult {
        Err(LxError::EINVAL)
    }
    /// missing documentation
    async fn accept(&self) -> LxResult<(Arc<dyn FileLike>, Endpoint)> {
        Err(LxError::EINVAL)
    }
    /// missing documentation
    fn endpoint(&self) -> Option<Endpoint> {
        None
    }
    /// missing documentation
    fn remote_endpoint(&self) -> Option<Endpoint> {
        None
    }
    /// missing documentation
    fn setsockopt(&self, _level: usize, _opt: usize, _data: &[u8]) -> SysResult {
        warn!("setsockopt is unimplemented");
        Ok(0)
    }
    /// missing documentation
    fn ioctl(&self, _request: usize, _arg1: usize, _arg2: usize, _arg3: usize) -> SysResult {
        warn!("ioctl is unimplemented for this socket");
        Ok(0)
    }
    /// Get Socket recv and send buffer capacity
    fn get_buffer_capacity(&self) -> Option<(usize, usize)> {
        None
    }
    /// Get Socket Type
    fn socket_type(&self) -> Option<SocketType> {
        None
    }
}

downcast_rs::impl_downcast!(sync Socket);

/*
bitflags::bitflags! {
    /// Socket flags
    #[derive(Default)]
    struct SocketFlags: usize {
        const SOCK_NONBLOCK = 0x800;
        const SOCK_CLOEXEC = 0x80000;
    }
}

impl From<SocketFlags> for OpenOptions {
    fn from(flags: SocketFlags) -> OpenOptions {
        OpenOptions {
            nonblock: flags.contains(SocketFlags::SOCK_NONBLOCK),
            close_on_exec: flags.contains(SocketFlags::SOCK_CLOEXEC),
        }
    }
}
*/
