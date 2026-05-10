use crate::{
    error::{LxError, LxResult},
    fs::{FileLike, OpenFlags, PollEvents, PollStatus},
    net::*,
};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use async_trait::async_trait;
use kernel_hal::drivers::prelude::DeviceError;
use kernel_hal::user::UserInOutPtr;
use kernel_hal::{drivers, thread};
use lock::Mutex;
use zircon_object::object::*;
use lazy_static::lazy_static;
use smoltcp::wire::EthernetFrame;

// Global list of active AF_PACKET sockets to implement packet tapping.
lazy_static! {
    static ref PACKET_SOCKETS: Mutex<Vec<Weak<PacketSocketState>>> = Mutex::new(Vec::new());
}

pub struct PacketSocketState {
    base: KObjectBase,
    flags: Mutex<OpenFlags>,
    /// Index (1-based) of the bound interface; 0 = unbound.
    ifindex: Mutex<u32>,
}

impl PacketSocketState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            base: KObjectBase::new(),
            flags: Mutex::new(OpenFlags::RDWR),
            ifindex: Mutex::new(0),
        })
    }
}

#[async_trait]
impl Socket for PacketSocketState {
    async fn read(&self, data: &mut [u8]) -> (SysResult, Endpoint) {
        let mut endpoint = Endpoint::LinkLevel(LinkLevelEndpoint::new(*self.ifindex.lock() as usize));
        let non_block = self.flags.lock().contains(OpenFlags::NON_BLOCK);

        loop {
            let dev = match drivers::all_net().first() {
                Some(d) => d,
                None => return (Err(LxError::ENODEV), endpoint),
            };

            match dev.recv(data) {
                Ok(n) => {
                    // Try to parse Ethernet header to extract source MAC
                    if let Ok(frame) = EthernetFrame::new_checked(&data[..n]) {
                        if let Endpoint::LinkLevel(ref mut ll) = endpoint {
                            ll.addr[..6].copy_from_slice(frame.src_addr().as_bytes());
                            ll.halen = 6;
                        }
                    }
                    return (Ok(n), endpoint);
                }
                Err(DeviceError::NotReady) => {
                    if non_block {
                        return (Err(LxError::EAGAIN), endpoint);
                    }
                }
                Err(_) => return (Err(LxError::EIO), endpoint),
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
        let dev = drivers::all_net().first();
        let readable = dev.as_ref().map_or(false, |d| d.can_recv());
        let writable = dev.as_ref().map_or(false, |d| d.can_send());
        (readable, writable, false)
    }

    fn ioctl(&self, request: usize, arg1: usize, _arg2: usize, _arg3: usize) -> SysResult {
        match request {
            SIOCGIFINDEX => {
                let mut ifr = UserInOutPtr::<IfReq>::from(arg1);
                let data = ifr.read()?;
                let if_name = data.name();
                let ifaces = drivers::all_net();
                for (i, iface) in ifaces.as_vec().iter().enumerate() {
                    if iface.get_ifname() == if_name {
                        let mut data = data;
                        data.ifr_ifru.ifindex = (i + 1) as i32;
                        ifr.write(data)?;
                        return Ok(0);
                    }
                }
                Err(LxError::ENODEV)
            }
            SIOCGIFFLAGS => {
                let mut ifr = UserInOutPtr::<IfReq>::from(arg1);
                let data = ifr.read()?;
                let mut data = data;
                // For now, all interfaces are always UP and RUNNING.
                // We also assume they support BROADCAST and MULTICAST.
                data.ifr_ifru.flags = (IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST) as i16;
                ifr.write(data)?;
                Ok(0)
            }
            SIOCSIFFLAGS => {
                // Ignore for now, but return success to satisfy tools.
                Ok(0)
            }
            SIOCGIFADDR => {
                let mut ifr = UserInOutPtr::<IfReq>::from(arg1);
                let data = ifr.read()?;
                let if_name = data.name();
                let ifaces = drivers::all_net();
                for iface in ifaces.as_vec().iter() {
                    if iface.get_ifname() == if_name {
                        let mut data = data;
                        let ip = iface.get_ip_address().iter().find_map(|cidr| match cidr {
                            smoltcp::wire::IpCidr::Ipv4(cidr) => Some(cidr.address()),
                            _ => None,
                        }).unwrap_or(smoltcp::wire::Ipv4Address::UNSPECIFIED);
                        
                        data.ifr_ifru.addr.sin_family = AddressFamily::Internet.into();
                        data.ifr_ifru.addr.sin_port = 0;
                        data.ifr_ifru.addr.sin_addr = u32::from_ne_bytes(ip.0);
                        
                        ifr.write(data)?;
                        return Ok(0);
                    }
                }
                Err(LxError::ENODEV)
            }
            SIOCGIFHWADDR => {
                let mut ifr = UserInOutPtr::<IfReq>::from(arg1);
                let data = ifr.read()?;
                let if_name = data.name();
                let ifaces = drivers::all_net();
                for iface in ifaces.as_vec().iter() {
                    if iface.get_ifname() == if_name {
                        let mut data = data;
                        let mac = iface.get_mac();
                        unsafe {
                            data.ifr_ifru.hwaddr.sa_family = ARPHRD_ETHER;
                            data.ifr_ifru.hwaddr.sa_data[..6].copy_from_slice(mac.as_bytes());
                        }
                        ifr.write(data)?;
                        return Ok(0);
                    }
                }
                Err(LxError::ENODEV)
            }
            _ => Ok(0),
        }
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
        let mut flags = self.flags.lock();
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
