use std::ffi::c_int;
use std::{io, mem};
use std::io::{IoSlice, IoSliceMut, Result};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsFd, AsRawFd};
use socket2::{Domain, Socket, Type};

#[cfg(unix)]
use nix::sys::socket;

/// Ipv4 udp socket with capability to send/receive packets on specific interfaces.
pub struct MultiInterfaceSocket {
    socket: Socket,
}
#[cfg(unix)]
fn nix_to_io_error(e: nix::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e)
}

impl MultiInterfaceSocket {
    pub fn bind_any() -> Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
        socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into())?;

        #[cfg(unix)]
        socket::setsockopt(&socket.as_fd(), socket::sockopt::Ipv4PacketInfo, &true)
            .map_err(nix_to_io_error)?;

        Ok(Self {
            socket
        })
    }
    
    pub fn bind_port(port: u16) -> Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
        socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into())?;

        #[cfg(unix)]
        socket::setsockopt(&socket.as_fd(), socket::sockopt::Ipv4PacketInfo, &true)
            .map_err(nix_to_io_error)?;

        Ok(Self {
            socket
        })
    }
    pub fn bind(addr: SocketAddrV4) -> Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
        socket.bind(&addr.into())?;

        #[cfg(unix)]
        socket::setsockopt(&socket.as_fd(), socket::sockopt::Ipv4PacketInfo, &true)
            .map_err(nix_to_io_error)?;

        Ok(Self {
            socket
        })
    }
    
    pub fn get_bind_addr(&self) -> Result<SocketAddrV4> {
        let addr = self.socket.local_addr()?;
        if let Some(addr) = addr.as_socket_ipv4() {
            Ok(addr)
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "Not an IPv4 address"))
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

    /// `recvfrom`, but with interface index.
    #[cfg(unix)]
    pub fn recv_from_iface<'a>(&self, buf: &'a mut [u8]) -> Result<(&'a mut [u8], Option<SocketAddrV4>, c_int)> {
        let mut control_buffer = nix::cmsg_space!(nix::libc::in_pktinfo);
        let mut bufs = [IoSliceMut::new(buf)];
        let message: socket::RecvMsg<socket::SockaddrIn> = socket::recvmsg(
            self.socket.as_raw_fd(),
            &mut bufs,
            Some(&mut control_buffer),
            socket::MsgFlags::empty(),
        )
            .map_err(nix_to_io_error)?;

        let dst_addr = message.address.map(|a| SocketAddrV4::new(a.ip(), a.port()));
        let sz = message.bytes;

        let mut index = 0;
        for cmsg in message.cmsgs()? {
            if let socket::ControlMessageOwned::Ipv4PacketInfo(pkt_info) = cmsg {
                index = pkt_info.ipi_ifindex;
                break;
            }
        }
        Ok((&mut buf[..sz], dst_addr, index))
    }
    #[cfg(unix)]
    pub fn send_to_iface<'a>(&self, buf: &'a [u8], addr: SocketAddrV4, iface_index: c_int) -> Result<usize> {
        let bufs = [IoSlice::new(buf)];
        let mut pkt_info: nix::libc::in_pktinfo = unsafe { mem::zeroed() };
        pkt_info.ipi_ifindex = iface_index;

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