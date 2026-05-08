use super::*;
use core::mem::size_of;
use kernel_hal::user::UserInOutPtr;
use linux_object::{
    fs::{split_path, FileLike, OpenFlags},
    net::*,
};

impl Syscall<'_> {
    /// creates an endpoint for communication and returns a file descriptor that refers to that endpoint.
    pub fn sys_socket(&mut self, domain: usize, _type: usize, protocol: usize) -> SysResult {
        info!(
            "sys_socket: domain:{}, type:{}, protocol:{}",
            domain, _type, protocol
        );
        let domain = match Domain::try_from(domain) {
            Ok(domain) => domain,
            Err(_) => {
                warn!("sys_socket: invalid domain: {}", domain);
                return Err(LxError::EAFNOSUPPORT);
            }
        };
        let socket_type_val = _type & SOCKET_TYPE_MASK;
        let socket_type = match SocketType::try_from(socket_type_val) {
            Ok(t) => t,
            Err(_) => {
                warn!("sys_socket: invalid socket type: {:#x} (masked: {:#x})", _type, socket_type_val);
                return Err(LxError::EINVAL);
            }
        };
        // socket flags: SOCK_CLOEXEC SOCK_NONBLOCK
        let flags = OpenFlags::from_bits_truncate(_type & !SOCKET_TYPE_MASK);
        let protocol_num = protocol;
        let protocol = Protocol::try_from(protocol_num).ok();

        let socket: Arc<dyn FileLike> = match (domain, socket_type, protocol) {
            (Domain::AF_INET, SocketType::SOCK_STREAM, Some(Protocol::IPPROTO_IP))
            | (Domain::AF_INET, SocketType::SOCK_STREAM, Some(Protocol::IPPROTO_TCP)) => {
                Arc::new(TcpSocketState::new())
            }
            (Domain::AF_INET, SocketType::SOCK_DGRAM, Some(Protocol::IPPROTO_IP))
            | (Domain::AF_INET, SocketType::SOCK_DGRAM, Some(Protocol::IPPROTO_UDP)) => {
                Arc::new(UdpSocketState::new())
            }
            // Be tolerant for AF_INET datagram sockets.
            // Some userlands pass unexpected protocol numbers; for DHCP we only need UDP semantics.
            (Domain::AF_INET, SocketType::SOCK_DGRAM, None) => Arc::new(UdpSocketState::new()),
            // AF_INET raw sockets (some userlands probe these)
            (Domain::AF_INET, SocketType::SOCK_RAW, _) => {
                Arc::new(RawSocketState::new((protocol_num & 0xff) as u8))
            }
            // AF_NETLINK sockets for interface/address discovery (iproute-style)
            (Domain::AF_NETLINK, SocketType::SOCK_RAW, _)
            | (Domain::AF_NETLINK, SocketType::SOCK_DGRAM, _) => {
                Arc::new(NetlinkSocketState::default())
            }
            // AF_PACKET sockets (used by udhcpc for raw ethernet operations)
            (Domain::AF_PACKET, SocketType::SOCK_RAW, _)
            | (Domain::AF_PACKET, SocketType::SOCK_DGRAM, _) => Arc::new(PacketSocketState::new()),
            // AF_UNIX sockets
            (Domain::AF_UNIX, _, _) => UnixSocketState::new(),
            (_, _, _) => {
                info!(
                    "sys_socket: unsupported socket type: domain={:?}, type={:?}, protocol={:?}",
                    domain, socket_type, protocol_num
                );
                return Err(LxError::ENOSYS);
            }
        };
        socket.set_flags(flags)?;
        let fd = self.linux_process().add_socket(socket)?; // dyn FileLike
        Ok(fd.into())
    }

    ///  connects the socket referred to by the file descriptor sockfd to the address specified by addr.
    pub async fn sys_connect(
        &mut self,
        sockfd: usize,
        addr: UserInPtr<SockAddr>,
        addrlen: usize,
    ) -> SysResult {
        info!(
            "sys_connect: sockfd:{}, addr:{:?}, addrlen:{}",
            sockfd, addr, addrlen
        );
        let endpoint = sockaddr_to_endpoint(addr.read()?, addrlen)?;
        let proc = self.linux_process();
        let file_like = proc.get_file_like(sockfd.into())?;

        if let Endpoint::Unix(path) = &endpoint {
            if let Ok(unix) = file_like.clone().downcast_arc::<UnixSocketState>() {
                if let Some(server) = UnixSocketState::lookup(path) {
                    server.push_accept(unix);
                }
            }
        }

        file_like.clone().as_socket()?.connect(endpoint).await?;
        Ok(0)
    }

    /// set options for the socket referred to by the file descriptor sockfd.
    pub fn sys_setsockopt(
        &mut self,
        sockfd: usize,
        level: usize,
        optname: usize,
        optval: UserInPtr<u8>,
        optlen: usize,
    ) -> SysResult {
        info!(
            "sys_setsockopt: sockfd:{}, level:{}, optname:{}, optval:{:?} , optlen:{}",
            sockfd, level, optname, optval, optlen
        );
        let file_like = self.linux_process().get_file_like(sockfd.into())?;
        file_like
            .clone()
            .as_socket()?
            .setsockopt(level, optname, optval.as_slice(optlen)?)
    }

    /// get options for the socket referred to by the file descriptor sockfd.
    pub fn sys_getsockopt(
        &mut self,
        sockfd: usize,
        level: usize,
        optname: usize,
        mut optval: UserOutPtr<u32>,
        mut optlen: UserOutPtr<u32>,
    ) -> SysResult {
        info!(
            "sys_getsockopt: sockfd:{}, level:{}, optname:{}, optval:{:?} , optlen:{:?}",
            sockfd, level, optname, optval, optlen
        );
        let level = match Level::try_from(level) {
            Ok(level) => level,
            Err(_) => {
                error!("invalid level: {}", level);
                return Err(LxError::ENOPROTOOPT);
            }
        };
        if optval.is_null() {
            return Err(LxError::EINVAL);
        }
        match level {
            Level::SOL_SOCKET => {
                let optname = match SolOptname::try_from(optname) {
                    Ok(optname) => optname,
                    Err(_) => {
                        error!("invalid optname: {}", optname);
                        return Err(LxError::ENOPROTOOPT);
                    }
                };

                let file_like = self.linux_process().get_file_like(sockfd.into())?;
                let (recv_buf_ca, send_buf_ca) = file_like
                    .clone()
                    .as_socket()?
                    .get_buffer_capacity()
                    .unwrap();
                debug!("sys_getsockopt recv and send buffer capacity: {}, {}. optval: {:?}, optlen: {:?}", recv_buf_ca, send_buf_ca, optval.check(), optlen.check());

                match optname {
                    SolOptname::SNDBUF => {
                        optval.write(send_buf_ca as u32)?;
                        optlen.write(size_of::<u32>() as u32)?;
                        Ok(0)
                    }
                    SolOptname::RCVBUF => {
                        optval.write(recv_buf_ca as u32)?;
                        optlen.write(size_of::<u32>() as u32)?;
                        Ok(0)
                    }
                    SolOptname::REUSEADDR => {
                        optval.write(1)?;
                        optlen.write(size_of::<u32>() as u32)?;
                        Ok(0)
                    }
                    SolOptname::ERROR => {
                        optval.write(0)?;
                        optlen.write(size_of::<u32>() as u32)?;
                        Ok(0)
                    }
                    _ => Err(LxError::ENOPROTOOPT),
                }
            }
            Level::IPPROTO_TCP => {
                let optname = match TcpOptname::try_from(optname) {
                    Ok(optname) => optname,
                    Err(_) => {
                        error!("invalid optname: {}", optname);
                        return Err(LxError::ENOPROTOOPT);
                    }
                };
                match optname {
                    TcpOptname::CONGESTION => Ok(0),
                }
            }
            Level::IPPROTO_IP => {
                let optname = match IpOptname::try_from(optname) {
                    Ok(optname) => optname,
                    Err(_) => {
                        error!("invalid optname: {}", optname);
                        return Err(LxError::ENOPROTOOPT);
                    }
                };
                match optname {
                    IpOptname::HDRINCL => unimplemented!(),
                }
            }
        }
    }

    /// transmit a message to another socket
    pub fn sys_sendto(
        &mut self,
        sockfd: usize,
        buf: UserInPtr<u8>,
        len: usize,
        flags: usize,
        dest_addr: UserInPtr<SockAddr>,
        addrlen: usize,
    ) -> SysResult {
        info!(
            "sys_sendto: sockfd:{:?}, buffer:{:?}, length:{:?}, flags:{:?} , optlen:{:?}, addrlen:{:?}",
            sockfd, buf, len, flags, dest_addr, addrlen
        );
        let endpoint = if dest_addr.is_null() {
            None
        } else {
            let endpoint = sockaddr_to_endpoint(dest_addr.read()?, addrlen)?;
            Some(endpoint)
        };
        let file_like = self.linux_process().get_file_like(sockfd.into())?;
        file_like
            .clone()
            .as_socket()?
            .write(buf.as_slice(len)?, endpoint)?;
        Ok(len)
    }

    /// receive messages from a socket
    pub async fn sys_recvfrom(
        &mut self,
        sockfd: usize,
        mut buf: UserOutPtr<u8>,
        len: usize,
        flags: usize,
        src_addr: UserOutPtr<SockAddr>,
        addrlen: UserInOutPtr<u32>,
    ) -> SysResult {
        let _ = self.maybe_handle_tty_intr()?;
        info!(
            "sys_recvfrom: sockfd:{}, buffer:{:?}, length:{}, flags:{} , src_addr:{:?}, addrlen:{:?}",
            sockfd, buf, len, flags, src_addr, addrlen
        );
        let file_like = self.linux_process().get_file_like(sockfd.into())?;
        debug!("FileLike {} flags: {:?}", sockfd, file_like.flags());
        let mut data = vec![0u8; len];
        let (result, endpoint) = file_like.clone().as_socket()?.read(&mut data).await;
        if result.is_ok() && !src_addr.is_null() {
            let sockaddr_in = SockAddr::from(endpoint);
            sockaddr_in.write_to(src_addr, addrlen)?;
        }
        buf.write_array(&data[..len])?;
        result
    }

    /// transmit a message to another socket
    #[allow(unsafe_code)]
    pub fn sys_sendmsg(
        &mut self,
        sockfd: usize,
        msg: UserInPtr<MsgHdr>,
        flags: usize,
    ) -> SysResult {
        info!(
            "sys_sendmsg: sockfd:{}, msg:{:?}, flags:{}",
            sockfd, msg, flags
        );
        let hdr = msg.read()?;
        let iov_ptr: UserInPtr<IoVecIn> = unsafe { core::mem::transmute(hdr.msg_iov) };
        let iovlen = hdr.msg_iovlen;
        let iovs = iov_ptr.read_iovecs(iovlen)?;
        let data = iovs.read_to_vec()?;

        let endpoint = if !hdr.msg_name.is_null() {
            let endpoint = sockaddr_to_endpoint(hdr.msg_name.read()?, hdr.msg_namelen as usize)?;
            Some(endpoint)
        } else {
            None
        };

        let file_like = self.linux_process().get_file_like(sockfd.into())?;
        file_like.clone().as_socket()?.write(&data, endpoint)?;
        Ok(data.len())
    }

    /// receive messages from a socket
    pub async fn sys_recvmsg(
        &mut self,
        sockfd: usize,
        msg: UserInOutPtr<MsgHdr>,
        flags: usize,
    ) -> SysResult {
        info!(
            "sys_recvmsg: sockfd:{}, msg:{:?}, flags:{}",
            sockfd, msg, flags
        );
        let hdr = msg.read()?;

        let iov_ptr = hdr.msg_iov;
        let iovlen = hdr.msg_iovlen;
        let mut iovs = iov_ptr.read_iovecs(iovlen)?;
        let mut data = vec![0u8; iovs.total_len()];

        let file_like = self.linux_process().get_file_like(sockfd.into())?;
        let (result, endpoint) = file_like.clone().as_socket()?.read(&mut data).await;

        let addr = hdr.msg_name;
        if let Ok(len) = result {
            iovs.write_from_buf(&data[..len])?;
            if !addr.is_null() {
                let sockaddr_in = SockAddr::from(endpoint);
                sockaddr_in.write_to_msg(msg)?;
            }
        }

        result
    }

    /// assigns the address specified by addr to the socket referred to by the file descriptor sockfd
    pub fn sys_bind(
        &mut self,
        sockfd: usize,
        addr: UserInPtr<SockAddr>,
        addrlen: usize,
    ) -> SysResult {
        info!(
            "sys_bind: sockfd:{:?}, addr:{:?}, addrlen:{}",
            sockfd, addr, addrlen
        );
        let endpoint = sockaddr_to_endpoint(addr.read()?, addrlen)?;
        debug!("sys_bind: fd:{} bind to {:?}", sockfd, endpoint);

        let proc = self.linux_process();
        if let Endpoint::Unix(path) = &endpoint {
            if !path.is_empty() {
                let (dir_path, file_name) = split_path(path);
                if let Ok(dir_inode) = proc.lookup_inode_at(FileDesc::CWD, dir_path, true) {
                    if dir_inode.find(file_name).is_err() {
                        dir_inode.create(
                            file_name,
                            linux_object::fs::vfs::FileType::Socket,
                            0o666,
                        ).map_err(|e| {
                            warn!("sys_bind: failed to create socket node {:?}: {:?}", file_name, e);
                            e
                        })?;
                    }
                } else {
                    warn!("sys_bind: failed to lookup directory: {:?} (original path: {:?})", dir_path, path);
                    return Err(LxError::ENOENT);
                }

                let file_like = proc.get_file_like(sockfd.into())?;
                if let Ok(unix) = file_like.clone().downcast_arc::<UnixSocketState>() {
                    UnixSocketState::register(path.clone(), unix)?;
                }
            }
        }

        let file_like = proc.get_file_like(sockfd.into())?;
        file_like.clone().as_socket()?.bind(endpoint)
    }

    /// marks the socket referred to by sockfd as a passive socket,
    /// that is, as a socket that will be used to accept incoming connection
    pub fn sys_listen(&mut self, sockfd: usize, backlog: usize) -> SysResult {
        info!("sys_listen: fd:{}, backlog:{}", sockfd, backlog);
        // smoltcp tcp sockets do not support backlog
        // open multiple sockets for each connection
        let file_like = self.linux_process().get_file_like(sockfd.into())?;
        file_like.clone().as_socket()?.listen()
    }

    /// shutdown a socket
    pub fn sys_shutdown(&mut self, sockfd: usize, howto: usize) -> SysResult {
        info!("sys_shutdown: sockfd:{}, howto:{}", sockfd, howto);
        // todo: how to use 'howto'
        let file_like = self.linux_process().get_file_like(sockfd.into())?;
        file_like.clone().as_socket()?.shutdown()
    }

    /// accept() is used with connection-based socket types (SOCK_STREAM, SOCK_SEQPACKET).
    /// It extracts the first connection request on the queue of pending connections
    /// for the listening socket, sockfd, creates a new connected socket, and returns
    /// a new file descriptor referring to that socket.
    /// The newly created socket is not in the listening state.
    /// The original socket sockfd is unaffected by this call.
    pub async fn sys_accept(
        &mut self,
        sockfd: usize,
        addr: UserOutPtr<SockAddr>,
        addrlen: UserInOutPtr<u32>,
    ) -> SysResult {
        info!(
            "sys_accept: sockfd:{}, addr:{:?}, addrlen={:?}",
            sockfd, addr, addrlen
        );
        // smoltcp tcp sockets do not support backlog
        // open multiple sockets for each connection
        let file_like = self.linux_process().get_file_like(sockfd.into())?;
        let (new_socket, remote_endpoint) = file_like.clone().as_socket()?.accept().await?;
        debug!(
            "FileLike{} flags: {:?}, New flags: {:?}",
            sockfd,
            file_like.flags(),
            new_socket.flags()
        );

        let new_fd = self.linux_process().add_socket(new_socket)?;
        if !addr.is_null() {
            let sockaddr_in = SockAddr::from(remote_endpoint);
            sockaddr_in.write_to(addr, addrlen)?;
        }
        Ok(new_fd.into())
    }

    /// returns the current address to which the socket sockfd is bound,
    /// in the buffer pointed to by addr.
    pub fn sys_getsockname(
        &mut self,
        sockfd: usize,
        addr: UserOutPtr<SockAddr>,
        addrlen: UserInOutPtr<u32>,
    ) -> SysResult {
        info!(
            "sys_getsockname: sockfd:{}, addr:{:?}, addrlen:{:?}",
            sockfd, addr, addrlen
        );
        if addr.is_null() {
            return Err(LxError::EINVAL);
        }
        let file_like = self.linux_process().get_file_like(sockfd.into())?;
        let endpoint = file_like
            .clone()
            .as_socket()?
            .endpoint()
            .ok_or(LxError::EINVAL)?;
        SockAddr::from(endpoint).write_to(addr, addrlen)?;
        Ok(0)
    }

    /// returns the address of the peer connected to the socket sockfd,
    /// in the buffer pointed to by addr.
    pub fn sys_getpeername(
        &mut self,
        sockfd: usize,
        addr: UserOutPtr<SockAddr>,
        addrlen: UserInOutPtr<u32>,
    ) -> SysResult {
        info!(
            "sys_getpeername: sockfd:{}, addr:{:?}, addrlen:{:?}",
            sockfd, addr, addrlen
        );
        // smoltcp tcp sockets do not support backlog
        // open multiple sockets for each connection
        if addr.is_null() {
            return Err(LxError::EINVAL);
        }
        let file_like = self.linux_process().get_file_like(sockfd.into())?;
        let remote_endpoint = file_like
            .clone()
            .as_socket()?
            .remote_endpoint()
            .ok_or(LxError::EINVAL)?;
        SockAddr::from(remote_endpoint).write_to(addr, addrlen)?;
        Ok(0)
    }

    /// creates a pair of connected sockets in the specified domain, of the specified type, 
    /// and using the optionally specified protocol.
    pub fn sys_socketpair(
        &mut self,
        domain: usize,
        _type: usize,
        protocol: usize,
        mut sv: UserOutPtr<i32>,
    ) -> SysResult {
        info!(
            "sys_socketpair: domain:{}, type:{}, protocol:{}",
            domain, _type, protocol
        );
        if domain != Domain::AF_UNIX as usize {
            return Err(LxError::EAFNOSUPPORT);
        }
        let proc = self.linux_process();
        let socket1 = Arc::new(UnixSocketState::default());
        let socket2 = Arc::new(UnixSocketState::default());
        UnixSocketState::connect_to(&socket1, &socket2);
        let fd1 = proc.add_socket(socket1)?;
        let fd2 = proc.add_socket(socket2)?;
        sv.write_array(&[fd1.into(), fd2.into()])?;
        Ok(0)
    }
}
