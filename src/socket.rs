use std::io;
use std::io::{IoSlice, IoSliceMut, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
#[cfg(depend_nix)]
use nix::sys::socket;

/// Ipv4 udp socket with capability to send/receive packets on specific interfaces.
pub struct MultiInterfaceSocket {
    socket: Socket,
    #[cfg(windows)]
    wsa_structs: win_helper::WSAStructs
}
#[cfg(depend_nix)]
fn nix_to_io_error(e: nix::Error) -> io::Error {
    io::Error::other(e)
}

#[cfg(windows)]
#[path("./win_specific.rs")]
mod win_helper;

impl MultiInterfaceSocket {
    pub fn bind_any() -> Result<Self> {
        Self::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
    }
    
    pub fn bind_port(port: u16) -> Result<Self> {
        Self::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))
    }
    pub fn bind(addr: SocketAddrV4) -> Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.bind(&addr.into())?;

        #[cfg(depend_nix)]
        use std::os::fd::AsFd;
        #[cfg(depend_nix)]
        socket::setsockopt(&socket.as_fd(), socket::sockopt::Ipv4PacketInfo, &true)
            .map_err(nix_to_io_error)?;

        #[cfg(windows)]
        let wsa_structs = win_helper::win_init(&socket)?;

        Ok(Self {
            socket,
            #[cfg(windows)]
            wsa_structs
        })
    }
    
    pub fn get_bind_addr(&self) -> Result<SocketAddrV4> {
        let addr = self.socket.local_addr()?;
        if let Some(addr) = addr.as_socket_ipv4() {
            Ok(addr)
        } else {
            Err(io::Error::other("Not an IPv4 address"))
        }
    }
    
    /// Join a multicast group on provided interface. 
    pub fn join_multicast_group(&self, addr: Ipv4Addr, interface: Ipv4Addr) -> Result<()> {
        self.socket.join_multicast_v4(&addr, &interface)
    }

    /// Leave a multicast group on provided interface. 
    pub fn leave_multicast_group(&self, addr: Ipv4Addr, interface: Ipv4Addr) -> Result<()> {
        self.socket.leave_multicast_v4(&addr, &interface)
    }
    
    /// Nonblocking mode will cause read operations to return immediately with an error if no data is available.
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        self.socket.set_nonblocking(nonblocking)
    }
    /// Assign a timeout to read operations on the socket.
    pub fn set_read_timeout(&self, timeout: std::time::Duration) -> Result<()> {
        self.socket.set_read_timeout(Some(timeout))
    }
    /// When socket is non-blocking, this option will cause the read operation to block indefinitely until data is available.
    pub fn set_read_timeout_inf(&self) -> Result<()> {
        self.socket.set_read_timeout(None)
    }

}

#[cfg(depend_nix)]
impl MultiInterfaceSocket {
    /// `recvfrom`, but with interface index.
    pub fn recv_from_iface<'a>(&self, buf: &'a mut [u8]) -> Result<(&'a mut [u8], SocketAddrV4, u32)> {
        use std::os::fd::AsRawFd;

        let mut control_buffer = nix::cmsg_space!(nix::libc::in_pktinfo);
        let mut bufs = [IoSliceMut::new(buf)];
        let message: socket::RecvMsg<socket::SockaddrIn> = socket::recvmsg(
            self.socket.as_raw_fd(),
            &mut bufs,
            Some(&mut control_buffer),
            socket::MsgFlags::empty(),
        )
            .map_err(nix_to_io_error)?;

        let dst_addr = message.address.map(|a| SocketAddrV4::new(a.ip(), a.port()))
            .unwrap_or(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
        let sz = message.bytes;

        let mut index = 0;
        for cmsg in message.cmsgs()? {
            if let socket::ControlMessageOwned::Ipv4PacketInfo(pkt_info) = cmsg {
                index = pkt_info.ipi_ifindex as u32;
                break;
            }
        }
        Ok((&mut buf[..sz], dst_addr, index))
    }


    #[cfg(depend_nix)]
    pub fn send_to_iface(&self, buf: &[u8], addr: SocketAddrV4, iface_index: u32, _source_if_addr: IpAddr) -> Result<usize> {
        use std::os::fd::AsRawFd;

        let bufs = [IoSlice::new(buf)];
        let mut pkt_info: nix::libc::in_pktinfo = unsafe { std::mem::zeroed() };
        pkt_info.ipi_ifindex = iface_index as i32;

        socket::sendmsg(
            self.socket.as_raw_fd(),
            &bufs,
            &[socket::ControlMessage::Ipv4PacketInfo(&pkt_info)],
            socket::MsgFlags::empty(),
            Some(&socket::SockaddrIn::from(addr)),
        )
            .map_err(nix_to_io_error)
    }
}
#[cfg(windows)]
impl MultiInterfaceSocket {
    /// `recvfrom`, but with interface index.
    pub fn recv_from_iface<'a>(&self, buf: &'a mut [u8]) -> Result<(&'a mut [u8], SocketAddrV4, u32)> {
        let (sz, addr, iface) = self.wsa_structs.receive(buf, &self.socket)?;
        Ok((&mut buf[..sz], addr, iface))
    }
    pub fn send_to_iface(&self, buf: &[u8], addr: SocketAddrV4, iface_index: u32, source_if_addr: IpAddr) -> Result<usize> {
        if let IpAddr::V4(source_ip_addr) = source_if_addr {
            self.wsa_structs.send(buf, addr, iface_index, source_ip_addr, &self.socket)
        }
        else {
            Err(io::Error::other("Not an IPv4 address"))
        }
    }

}
#[cfg(use_fallback_impl)]
fn convert_buf(buf: &mut [u8]) -> &mut [std::mem::MaybeUninit<u8>] {
    unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut std::mem::MaybeUninit<u8>, buf.len()) }
}
// Fallback implementation
#[cfg(use_fallback_impl)]
impl MultiInterfaceSocket {
    pub fn recv_from_iface<'a>(&self, buf: &'a mut [u8]) -> Result<(&'a mut [u8], SocketAddrV4, u32)> {
        let (sz, addr) = self.socket.recv_from(convert_buf(buf))?;

        if let Some(addr) = addr.as_socket_ipv4() {
            Ok((&mut buf[..sz], addr, 1))
        }
        else {
            Err(io::Error::other("Not an IPv4 address"))
        }

    }
    pub fn send_to_iface(&self, buf: &[u8], addr: SocketAddrV4, iface_index: u32, source_if_addr: IpAddr) -> Result<usize> {
        self.socket.send_to(buf, &SockAddr::from(addr))
    }
}
