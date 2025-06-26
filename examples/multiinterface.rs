use std::net::Ipv4Addr;
use log::info;
use multicast_discovery_socket::socket::MultiInterfaceSocket;

fn main() {
    simple_logger::init_with_level(log::Level::Info).unwrap();

    let sock1 = MultiInterfaceSocket::bind_any().unwrap();
    let sock2 = MultiInterfaceSocket::bind_any().unwrap();

    let mut addr1 = sock1.get_bind_addr().unwrap();
    let mut addr2 = sock2.get_bind_addr().unwrap();
    addr1.set_ip(Ipv4Addr::new(127, 0, 0, 1));
    addr2.set_ip(Ipv4Addr::new(127, 0, 0, 1));
    info!("Socket 1 bound to: {}", addr1);
    info!("Socket 2 bound to: {}", addr2);

    // Send to the default system interface
    sock2.send_to_iface(b"Hello from sock2", addr1, 0).unwrap();
    let mut buf = [0u8; 1024];
    let (buf, addr, iface) = sock1.recv_from_iface(&mut buf).unwrap();
    let msg = String::from_utf8_lossy(buf);
    info!("Received message on sock1: {}", msg);
    info!("From address: {:?}, on interface: {}", addr, iface);

    // Reply to the same interface we got the message from
    sock1.send_to_iface(b"Hello from sock1", addr2, iface).unwrap();
    let mut buf = [0u8; 1024];
    let (buf, addr, iface) = sock2.recv_from_iface(&mut buf).unwrap();
    let msg = String::from_utf8_lossy(buf);
    info!("Received message on sock2: {}", msg);
    info!("From address: {:?}, on interface: {}", addr, iface);
}