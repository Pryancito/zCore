use crate::{
    error::{LxError, LxResult},
    fs::{FileLike, OpenFlags, PollEvents, PollStatus},
    net::*,
};
use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use async_trait::async_trait;

// use kernel_hal::user::UserInOutPtr;
use kernel_hal::{drivers, thread};
use lock::Mutex;
use zircon_object::object::*;
use lazy_static::lazy_static;
use smoltcp::wire::{EthernetAddress, EthernetFrame};

lazy_static! {
    static ref PACKET_SOCKETS: Mutex<Vec<Weak<PacketSocketState>>> = Mutex::new(Vec::new());
}

/// Dispatches a received packet to all registered AF_PACKET sockets.
pub fn push_packet(packet: &[u8]) {
    let flag = kernel_hal::interrupt::intr_get();
    if flag { kernel_hal::interrupt::intr_off(); }
    let mut sockets = PACKET_SOCKETS.lock();
    let mut to_remove = Vec::new();

    for (i, weak) in sockets.iter().enumerate() {
        if let Some(state) = weak.upgrade() {
            let protocol = *state.inner.protocol.lock();
            // Try to parse Ethernet header to filter by protocol
            if let Ok(frame) = EthernetFrame::new_checked(packet) {
                let ethertype: u16 = frame.ethertype().into();
                
                // Snoop TCP SYN packets to populate listen_table
                if ethertype == 0x0800 { // IPv4
                    if let Ok(ipv4_packet) = smoltcp::wire::Ipv4Packet::new_checked(frame.payload()) {
                        if ipv4_packet.protocol() == smoltcp::wire::IpProtocol::Tcp {
                            if let Ok(tcp_packet) = smoltcp::wire::TcpPacket::new_checked(ipv4_packet.payload()) {
                                let is_first = tcp_packet.syn() && !tcp_packet.ack();
                                if is_first {
                                    use smoltcp::wire::{IpAddress, IpEndpoint};
                                    let src_addr = IpEndpoint::new(IpAddress::Ipv4(ipv4_packet.src_addr()), tcp_packet.src_port());
                                    let dst_addr = IpEndpoint::new(IpAddress::Ipv4(ipv4_packet.dst_addr()), tcp_packet.dst_port());
                                    
                                    if let Some(mut sockets) = zcore_drivers::net::get_sockets().try_lock() {
                                    crate::net::LISTEN_TABLE.incoming_tcp_packet(src_addr, dst_addr, &mut sockets);
                                    }
                                }
                            }
                        }
                    }
                }

                // Filter by protocol if not ETH_P_ALL (0x0003 in host order)
                if protocol != 0 && protocol != 0x0003 && protocol != ethertype {
                    continue;
                }

                let mut queue = state.inner.packet_queue.lock();
                // Limit queue size to avoid OOM
                if queue.len() < 1000 {
                    warn!("[packet] pushing packet to socket (type={:#x}, protocol={:#x}, len={})", ethertype, protocol, packet.len());
                    queue.push_back(packet.to_vec());
                    state.base.signal_set(Signal::READABLE);
                }
            }
        } else {
            to_remove.push(i);
        }
    }

    // Clean up dead weak pointers
    for i in to_remove.into_iter().rev() {
        sockets.swap_remove(i);
    }
    
    if flag { kernel_hal::interrupt::intr_on(); }
}

pub struct PacketSocketState {
    base: KObjectBase,
    inner: Arc<PacketSocketInner>,
}

#[derive(Debug)]
struct PacketSocketInner {
    flags: Mutex<OpenFlags>,
    ifindex: Mutex<u32>,
    socket_type: SocketType,
    protocol: Mutex<u16>,
    packet_queue: Mutex<VecDeque<Vec<u8>>>,
}

impl PacketSocketState {
    pub fn new(socket_type: SocketType, protocol: u16) -> Arc<Self> {
        let state = Arc::new(Self {
            base: KObjectBase::with_signal(Signal::WRITABLE),
            inner: Arc::new(PacketSocketInner {
                flags: Mutex::new(OpenFlags::RDWR),
                ifindex: Mutex::new(0),
                socket_type,
                protocol: Mutex::new(protocol),
                packet_queue: Mutex::new(VecDeque::new()),
            }),
        });
        let flag = kernel_hal::interrupt::intr_get();
        if flag { kernel_hal::interrupt::intr_off(); }
        PACKET_SOCKETS.lock().push(Arc::downgrade(&state));
        if flag { kernel_hal::interrupt::intr_on(); }
        state
    }
}

#[async_trait]
impl Socket for PacketSocketState {
    async fn read(&self, data: &mut [u8]) -> (SysResult, Endpoint) {
        let mut endpoint = Endpoint::LinkLevel(LinkLevelEndpoint::new(*self.inner.ifindex.lock() as usize));
        let non_block = self.inner.flags.lock().contains(OpenFlags::NON_BLOCK);

        loop {
            // Drain any deferred jobs first (IRQ handlers queue iface.poll here on real hardware)
            kernel_hal::deferred_job::drain_deferred_jobs();

            let ifindex = *self.inner.ifindex.lock();
            if self.inner.packet_queue.lock().is_empty() {
                let ifaces = drivers::all_net();
                if ifindex > 0 {
                    if let Some(net) = ifaces.try_get(ifindex as usize - 1) {
                        let _ = net.poll();
                    }
                } else {
                    for net in ifaces.as_vec().iter() {
                        let _ = net.poll();
                    }
                }
            }

            let pkt = self.inner.packet_queue.lock().pop_front();
            if let Some(internal_buf) = pkt {
                let n = internal_buf.len();
                let mut start = 0;
                // Try to parse Ethernet header to extract source MAC
                if let Ok(frame) = EthernetFrame::new_checked(&internal_buf[..n]) {
                    let ethertype: u16 = frame.ethertype().into();
                    // Filters are already applied in push_packet, but we can double check or extract info
                    if let Endpoint::LinkLevel(ref mut ll) = endpoint {
                        ll.addr[..6].copy_from_slice(frame.src_addr().as_bytes());
                        ll.halen = 6;
                        ll.protocol = ethertype;
                    }
                    if self.inner.socket_type == SocketType::SOCK_DGRAM {
                        start = EthernetFrame::<&[u8]>::header_len();
                    }
                }
                let actual_len = n - start;
                let copy_len = actual_len.min(data.len());
                data[..copy_len].copy_from_slice(&internal_buf[start..start + copy_len]);

                if self.inner.packet_queue.lock().is_empty() {
                    self.base.signal_clear(Signal::READABLE);
                }

                return (Ok(actual_len), endpoint);
            }

            if non_block {
                return (Err(LxError::EAGAIN), endpoint);
            }

            // Drain deferred jobs (IRQ -> iface.poll -> push_packet) and then sleep a short
            // interval. On real hardware the NIC IRQ enqueues a deferred_job; draining here
            // ensures we don't miss a packet that arrived just before we slept.
            kernel_hal::deferred_job::drain_deferred_jobs();
            thread::sleep_until(kernel_hal::timer::timer_now() + core::time::Duration::from_millis(5)).await;
        }
    }
    fn write(&self, data: &[u8], sendto_endpoint: Option<Endpoint>) -> SysResult {
        let ifaces = drivers::all_net();
        let ifindex = *self.inner.ifindex.lock();
        let dev = if ifindex > 0 {
            ifaces.try_get(ifindex as usize - 1)
        } else {
            ifaces.first()
        }.ok_or(LxError::ENODEV)?;

        if self.inner.socket_type == SocketType::SOCK_DGRAM {
            if let Some(Endpoint::LinkLevel(ll)) = sendto_endpoint {
                let mut buf = vec![0u8; data.len() + 14];
                let mut frame = EthernetFrame::new_unchecked(&mut buf);
                frame.set_dst_addr(EthernetAddress::from_bytes(&ll.addr[..6]));
                frame.set_src_addr(dev.get_mac());
                let protocol_raw = if ll.protocol != 0 {
                    ll.protocol
                } else {
                    *self.inner.protocol.lock()
                };
                let protocol = protocol_raw;
                frame.set_ethertype(protocol.into());
                frame.payload_mut().copy_from_slice(data);
                dev.send(&buf).map_err(|_| LxError::EIO)?;
                info!("PacketSocket: sent {} bytes (DGRAM, proto (host)={:#x})", data.len(), protocol);
                return Ok(data.len());
            }
            // If no endpoint, we can't send SOCK_DGRAM (no destination MAC).
            return Err(LxError::EINVAL);
        }
        
        dev.send(data).map_err(|_| LxError::EIO)?;
        info!("PacketSocket: sent {} bytes (ifindex={})", data.len(), ifindex);
        Ok(data.len())
    }

    async fn connect(&self, _endpoint: Endpoint) -> SysResult {
        Err(LxError::EINVAL)
    }

    fn bind(&self, endpoint: Endpoint) -> SysResult {
        if let Endpoint::LinkLevel(ll) = endpoint {
            *self.inner.ifindex.lock() = ll.interface_index as u32;
            let proto = ll.protocol;
            *self.inner.protocol.lock() = proto;
            info!("PacketSocket: bound to ifindex {}, proto (host)={:#x}", ll.interface_index, proto);
            Ok(0)
        } else {
            Err(LxError::EINVAL)
        }
    }

    fn endpoint(&self) -> Option<Endpoint> {
        Some(Endpoint::LinkLevel(LinkLevelEndpoint::new(
            *self.inner.ifindex.lock() as usize,
        )))
    }

    fn remote_endpoint(&self) -> Option<Endpoint> {
        None
    }

    fn setsockopt(&self, _level: usize, _opt: usize, _data: &[u8]) -> SysResult {
        Ok(0)
    }

    fn poll(&self, _events: PollEvents) -> (bool, bool, bool) {
        let readable = !self.inner.packet_queue.lock().is_empty();
        let ifaces = drivers::all_net();
        let ifindex = *self.inner.ifindex.lock();
        let dev = if ifindex > 0 {
            ifaces.try_get(ifindex as usize - 1)
        } else {
            ifaces.first()
        };
        let writable = dev.as_ref().map_or(false, |d| d.can_send());
        (readable, writable, false)
    }

    fn ioctl(&self, request: usize, arg1: usize, arg2: usize, arg3: usize) -> SysResult {
        warn!("PacketSocket: ioctl request={:#x}, arg1={:#x}", request, arg1);
        handle_net_ioctl(request, arg1, arg2, arg3)
    }

    fn socket_type(&self) -> Option<SocketType> {
        Some(self.inner.socket_type)
    }
}

zircon_object::impl_kobject!(PacketSocketState);

#[async_trait]
impl FileLike for PacketSocketState {
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
        // Drain deferred jobs so IRQ-delivered packets are visible before reporting
        // readability. Without this, select/epoll can miss a DHCPOFFER that arrived
        // via the NIC interrupt while we were waiting.
        kernel_hal::deferred_job::drain_deferred_jobs();
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
