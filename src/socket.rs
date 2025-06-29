use std::io;
use std::io::{IoSlice, IoSliceMut, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use socket2::{Domain, Protocol, Socket, Type};
#[cfg(unix)]
use nix::sys::socket;

/// Ipv4 udp socket with capability to send/receive packets on specific interfaces.
pub struct MultiInterfaceSocket {
    socket: Socket,
    #[cfg(windows)]
    wsa_structs: win_helper::WSAStructs
}
#[cfg(unix)]
fn nix_to_io_error(e: nix::Error) -> io::Error {
    io::Error::other(e)
}

#[cfg(windows)]
mod win_helper {
    use std::ffi::{c_char, c_int};
    use std::{io, mem, ptr};
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::os::windows::io::RawSocket;
    use std::os::windows::prelude::AsRawSocket;
    use socket2::Socket;
    use winapi::shared::guiddef::GUID;
    use winapi::shared::inaddr::*;
    use winapi::shared::minwindef::DWORD;
    use winapi::shared::minwindef::{INT, LPDWORD};
    use winapi::shared::ws2def::LPWSAMSG;
    use winapi::shared::ws2def::*;
    use winapi::shared::ws2ipdef::*;
    use winapi::um::winsock2;
    use winapi::um::mswsock::{LPFN_WSARECVMSG, LPFN_WSASENDMSG, WSAID_WSARECVMSG, WSAID_WSASENDMSG};
    use winapi::um::winsock2::{LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE, SOCKET};

    fn last_error() -> io::Error {
        io::Error::from_raw_os_error(unsafe { winsock2::WSAGetLastError() })
    }

    unsafe fn setsockopt<T>(socket: RawSocket, opt: c_int, val: c_int, payload: T) -> io::Result<()>
    where
        T: Copy,
    {
        let payload = &payload as *const T as *const c_char;
        if winsock2::setsockopt(socket as _, opt, val, payload, mem::size_of::<T>() as c_int) == 0 {
            Ok(())
        } else {
            Err(last_error())
        }
    }
    type WSARecvMsgExtension = unsafe extern "system" fn(
        s: SOCKET,
        lpMsg: LPWSAMSG,
        lpdwNumberOfBytesRecvd: LPDWORD,
        lpOverlapped: LPWSAOVERLAPPED,
        lpCompletionRoutine: LPWSAOVERLAPPED_COMPLETION_ROUTINE,
    ) -> INT;
    type WSASendMsgExtension = unsafe extern "system" fn(
        s: SOCKET,
        lpMsg: LPWSAMSG,
        dwFlags: DWORD,
        lpNumberOfBytesSent: LPDWORD,
        lpOverlapped: LPWSAOVERLAPPED,
        lpCompletionRoutine: LPWSAOVERLAPPED_COMPLETION_ROUTINE,
    ) -> INT;
    
    unsafe fn get_fn_pointer(socket: RawSocket, guid: GUID, fn_pointer: &mut usize, byte_len: &mut u32) -> c_int {
        let fn_ptr = fn_pointer as *const _ as *mut _;
        winsock2::WSAIoctl(
            socket as _,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            &guid as *const _ as *mut _,
            mem::size_of_val(&guid) as DWORD,
            fn_ptr,
            mem::size_of_val(&fn_ptr) as DWORD,
            byte_len,
            ptr::null_mut(),
            None,
        )
    }
    
    fn locate_wsarecvmsg(socket: RawSocket) -> io::Result<WSARecvMsgExtension> {
        let mut fn_pointer: usize = 0;
        let mut byte_len: u32 = 0;

        let r = unsafe { get_fn_pointer(socket, WSAID_WSARECVMSG, &mut fn_pointer, &mut byte_len) };

        if r != 0 {
            return Err(io::Error::last_os_error());
        }

        if mem::size_of::<LPFN_WSARECVMSG>() != byte_len as _ {
            return Err(io::Error::other("Locating fn pointer to WSARecvMsg returned different expected bytes"));
        }
        let cast_to_fn: LPFN_WSARECVMSG = unsafe { mem::transmute(fn_pointer) };

        match cast_to_fn {
            None => Err(io::Error::other("WSARecvMsg extension not found")),
            Some(extension) => Ok(extension),
        }
    }

    fn locate_wsasendmsg(socket: RawSocket) -> io::Result<WSASendMsgExtension> {
        let mut fn_pointer: usize = 0;
        let mut byte_len: u32 = 0;

        let r = unsafe { get_fn_pointer(socket, WSAID_WSASENDMSG, &mut fn_pointer, &mut byte_len) };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }

        if mem::size_of::<LPFN_WSASENDMSG>() != byte_len as _ {
            return Err(io::Error::other("Locating fn pointer to WSASendMsg returned different expected bytes"));
        }
        let cast_to_fn: LPFN_WSASENDMSG = unsafe { mem::transmute(fn_pointer) };

        match cast_to_fn {
            None => Err(io::Error::other("WSASendMsg extension not found",
            )),
            Some(extension) => Ok(extension),
        }
    }
    pub struct WSAStructs {
        wsarecvmsg: WSARecvMsgExtension,
        wsasendmsg: WSASendMsgExtension,
    }


    fn set_pktinfo(socket: RawSocket, payload: bool) -> io::Result<()> {
        unsafe { setsockopt(socket, IPPROTO_IP, IP_PKTINFO, payload as c_int) }
    }

    fn to_s_addr(addr: &Ipv4Addr) -> in_addr_S_un {
        let octets = addr.octets();
        let res = u32::from_ne_bytes(octets);
        let mut new_addr: in_addr_S_un = unsafe { mem::zeroed() };
        unsafe { *(new_addr.S_addr_mut()) = res };
        new_addr
    }

    const CMSG_HEADER_SIZE: usize = size_of::<WSACMSGHDR>();
    const PKTINFO_DATA_SIZE: usize = size_of::<IN_PKTINFO>();
    const CONTROL_PKTINFO_BUFFER_SIZE: usize = CMSG_HEADER_SIZE + PKTINFO_DATA_SIZE;

    pub fn win_init(
        socket: &Socket
    ) -> io::Result<WSAStructs> {

        // enable fetching interface information and locate the extension function
        set_pktinfo(socket.as_raw_socket(), true)?;
        let wsarecvmsg: WSARecvMsgExtension = locate_wsarecvmsg(socket.as_raw_socket())?;
        let wsasendmsg: WSASendMsgExtension = locate_wsasendmsg(socket.as_raw_socket())?;

        Ok(WSAStructs {
            wsarecvmsg,
            wsasendmsg
        })
    }

    impl WSAStructs {
        pub fn receive(&self, data_buffer: &mut [u8], socket: &Socket) -> io::Result<(usize, SocketAddrV4, u32)> {
            let mut data = WSABUF {
                buf: data_buffer.as_mut_ptr() as *mut i8,
                len: data_buffer.len() as u32,
            };

            let mut control_buffer = [0; CONTROL_PKTINFO_BUFFER_SIZE];
            let control = WSABUF {
                buf: control_buffer.as_mut_ptr(),
                len: control_buffer.len() as u32,
            };

            let mut origin_address: SOCKADDR = unsafe { mem::zeroed() };
            let mut wsa_msg = WSAMSG {
                name: &mut origin_address,
                namelen: mem::size_of_val(&origin_address) as i32,
                lpBuffers: &mut data,
                Control: control,
                dwBufferCount: 1,
                dwFlags: 0,
            };

            let mut read_bytes = 0;
            let r = {
                unsafe {
                    (self.wsarecvmsg)(
                        socket.as_raw_socket() as _,
                        &mut wsa_msg,
                        &mut read_bytes,
                        ptr::null_mut(),
                        None,
                    )
                }
            };

            if r != 0 {
                return Err(io::Error::last_os_error());
            }

            let origin_address = if origin_address.sa_family != AF_INET as ADDRESS_FAMILY {
                SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)
            }
            else {
                let sa_data = origin_address.sa_data;

                // Extract port (network byte order -> big-endian)
                let port = u16::from_be_bytes([sa_data[0] as u8, sa_data[1] as u8]);

                // Extract IP bytes
                let ip = Ipv4Addr::new(
                    sa_data[2] as u8,
                    sa_data[3] as u8,
                    sa_data[4] as u8,
                    sa_data[5] as u8,
                );

                SocketAddrV4::new(ip, port) 
            };

            let mut index = 0;
            // Ensures that the control buffer is the size of the CSMG_HEADER + the pkinto data
            if control.len as usize == CONTROL_PKTINFO_BUFFER_SIZE {
                let cmsg_header: WSACMSGHDR = unsafe { ptr::read_unaligned(control.buf as *const _) };
                if cmsg_header.cmsg_level == IPPROTO_IP && cmsg_header.cmsg_type == IP_PKTINFO {
                    let interface_info: IN_PKTINFO =
                        unsafe { ptr::read_unaligned(control.buf.add(CMSG_HEADER_SIZE) as *const _) };
                    index = interface_info.ipi_ifindex;
                };
            };

            Ok((read_bytes as usize, origin_address, index))
        }

        pub fn send(&self, buf: &[u8], dst_addr: SocketAddrV4, iface_index: u32, source_if_addr: Ipv4Addr, socket: &Socket) -> io::Result<usize> {
            let pkt_info = IN_PKTINFO {
                ipi_addr: IN_ADDR {
                    S_un: to_s_addr(&source_if_addr),
                },
                ipi_ifindex: iface_index,
            };

            let mut data = WSABUF {
                buf: buf.as_ptr() as *mut _,
                len: buf.len() as _,
            };

            let mut control_buffer = [0; CONTROL_PKTINFO_BUFFER_SIZE];
            let hdr = CMSGHDR {
                cmsg_len: CONTROL_PKTINFO_BUFFER_SIZE,
                cmsg_level: IPPROTO_IP,
                cmsg_type: IP_PKTINFO,
            };
            unsafe {
                ptr::copy(
                    &hdr as *const _ as *const _,
                    control_buffer.as_mut_ptr(),
                    CMSG_HEADER_SIZE,
                );
                ptr::copy(
                    &pkt_info as *const _ as *const _,
                    control_buffer.as_mut_ptr().add(CMSG_HEADER_SIZE),
                    PKTINFO_DATA_SIZE,
                )
            };
            let control = WSABUF {
                buf: control_buffer.as_mut_ptr(),
                len: control_buffer.len() as _,
            };

            // Set custom port
            let destination = socket2::SockAddr::from(dst_addr);
            let destination_address = destination.as_ptr();
            let mut wsa_msg = WSAMSG {
                name: destination_address as *mut _,
                namelen: destination.len(),
                lpBuffers: &mut data,
                Control: control,
                dwBufferCount: 1,
                dwFlags: 0,
            };

            let mut sent_bytes = 0;
            let r = unsafe {
                (self.wsasendmsg)(
                    socket.as_raw_socket() as _,
                    &mut wsa_msg,
                    0,
                    &mut sent_bytes,
                    ptr::null_mut(),
                    None,
                )
            };
            if r != 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(sent_bytes as _)
        }
    }
}

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

        #[cfg(unix)]
        use std::os::fd::AsFd;
        #[cfg(unix)]
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

    /// `recvfrom`, but with interface index.
    #[cfg(unix)]
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

    /// `recvfrom`, but with interface index.
    #[cfg(windows)]
    pub fn recv_from_iface<'a>(&self, buf: &'a mut [u8]) -> Result<(&'a mut [u8], SocketAddrV4, u32)> {
        let (sz, addr, iface) = self.wsa_structs.receive(buf, &self.socket)?;
        Ok((&mut buf[..sz], addr, iface))
    }
    #[cfg(unix)]
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

    #[cfg(windows)]
    pub fn send_to_iface(&self, buf: &[u8], addr: SocketAddrV4, iface_index: u32, source_if_addr: IpAddr) -> Result<usize> {
        if let IpAddr::V4(source_ip_addr) = source_if_addr {
            self.wsa_structs.send(buf, addr, iface_index, source_ip_addr, &self.socket)
        }
        else {
            Err(io::Error::other("Not an IPv4 address"))
        }
    }
}

pub fn all_ipv4_interfaces() -> Result<Vec<Ipv4Addr>> {
    let interfaces = if_addrs::get_if_addrs()?
        .into_iter()
        .filter_map(|i| match i.ip() {
            std::net::IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
        .collect();
    Ok(interfaces)
}