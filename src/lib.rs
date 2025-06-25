pub mod config;
pub mod protocol;
pub mod socket;
// 
// use std::iter::once;
// use std::net::{Ipv4Addr, SocketAddrV4};
// use std::ops::Deref;
// pub use config::MulticastDiscoveryConfig;
// 
// use std::time::{Duration, Instant};
// use log::{info, trace, warn};
// use crate::protocol::{DiscoveryMessage, PollResult};
// use crate::socket::MultiInterfaceSocket;
// 
// const BG_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(3);
// const EXTENDED_ANNOUNCE_REQUEST_INTERVAL: Duration = Duration::from_secs(20);
// const EXTENDED_ANNOUNCE_EFFECT_DUR: Duration = Duration::from_secs(45);
// 
// pub struct MulticastDiscoverySocket {
//     socket: MultiInterfaceSocket,
//     local_port: u16,
//     cfg: MulticastDiscoveryConfig,
//     discover_id: u32,
//     running_port: MulticastRunningPort,
// 
//     central_discovery_enabled: bool,
//     announce_enabled: bool,
//     extend_disc_request_tm: Option<Instant>,
//     send_discovery_tm: Option<Instant>,
//     send_extend_request_tm: Option<Instant>,
// }
// 
// #[derive(Debug, Copy, Clone)]
// pub enum MulticastRunningPort {
//     Primary(u16),
//     Backup(u16),
//     Other
// }
// 
// impl Deref for MulticastRunningPort {
//     type Target = u16;
//     fn deref(&self) -> &Self::Target {
//         match self {
//             MulticastRunningPort::Primary(p) => p,
//             MulticastRunningPort::Backup(p) => p,
//             MulticastRunningPort::Other => &0,
//         }
//     }
// }
// 
// impl MulticastDiscoverySocket {
//     // Create new socket for multicast discovery. Announcements are enabled by default
//     pub fn new(cfg: &MulticastDiscoveryConfig, local_port: u16) -> anyhow::Result<Self> {
//         let central_discovery_enabled = cfg.central_discovery_addr.is_some();
//         let mut is_primary = true;
//         // Try primary and backup ports
//         let main_port = cfg.iter_ports().next().unwrap();
//         for port in cfg.iter_ports().chain(once(0)) {
//             let options = MulticastOptions {
//                 read_timeout: Some(Duration::from_millis(10)),
//                 reuse_addr: false,
// 
//                 ..Default::default()
//             };
// 
//             match MulticastSocket::with_options(
//                 SocketAddrV4::new(cfg.multicast_group_ip, port),
//                 all_ipv4_interfaces()?,
//                 options
//             ) {
//                 Ok(socket) => {
//                     let running_port = if is_primary {
//                         debug!("Using primary multicast port {} for discovery", port);
//                         MulticastRunningPort::Primary(port)
//                     }
//                     else if port == 0 {
//                         let failed_ports = cfg.iter_ports().filter(|p| *p != 0);
//                         warn!("Unable to start on the main or backup ports ({:?})!", &failed_ports.collect::<Vec<_>>());
//                         if !central_discovery_enabled {
//                             warn!("You will be unable to discover other clients!");
//                         }
//                         else {
//                             warn!("You will be able to discover clients only when your network is online!");
//                         }
//                         MulticastRunningPort::Other
//                     }
//                     else {
//                         warn!("Using backup multicast port {} for discovery (unable to start on main port {})", port, main_port);
//                         MulticastRunningPort::Backup(port)
//                     };
//                     return Ok(Self {
//                         socket,
//                         local_port,
//                         cfg: cfg.clone(),
//                         discover_id: rand::random_range(0..u32::MAX),
//                         running_port,
// 
//                         central_discovery_enabled,
//                         announce_enabled: cfg.enable_announce,
//                         extend_disc_request_tm: None,
//                         send_discovery_tm: None,
//                         send_extend_request_tm: None,
//                     })
//                 }
//                 Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
//                     is_primary = false;
//                     continue
//                 },
//                 Err(e) => {
//                     bail!("Failed to create multicast socket on port {}: {}", port, e);
//                 }
//             }
//         }
// 
//         bail!("Failed to create multicast socket on any of the configured ports: {:?}", cfg);
//     }
// 
//     pub fn discover_id(&self) -> u32 {
//         self.discover_id
//     }
//     pub fn running_port(&self) -> MulticastRunningPort {
//         self.running_port
//     }
// 
//     /// Setting this to `false` will disable both announcements and handling discovery packets
//     pub fn set_announce_en(&mut self, en: bool) {
//         self.announce_enabled = en;
//     }
// 
// 
//     /// Manually discover all clients on main or backup ports
//     pub fn discover(&mut self) {
//         info!("Multicast discovery: running manual discovery...");
//         let msg = DiscoveryMessage::Discovery.gen_message();
//         for interface in all_interfaces() {
//             let ports = once(self.cfg.multicast_port);
//             let ports = ports.chain(self.cfg.multicast_backup_ports.iter().copied());
//             for port in ports {
//                 if let Err(e) = self.socket.send_to_port(&msg, &Interface::Ip(interface), port) {
//                     warn!("Failed to send discovery message on interface {}: {}", interface, e);
//                 } else {
//                     trace!("Sent discovery message to port {} on interface {}", port, interface);
//                 }
//             }
//         }
//     }
//     pub fn poll(&mut self) -> PollResult {
//         self.try_poll().unwrap_or(PollResult::Nothing)
//     }
//     fn try_send_announce_packet(&mut self, disconnected: bool) {
//         if self.announce_enabled {
//             let is_extended_announcement = self.extend_disc_request_tm.is_some_and(|tm| tm.elapsed() < EXTENDED_ANNOUNCE_EFFECT_DUR);
//             if self.send_discovery_tm.is_none_or(|tm| Instant::now() > tm + BG_ANNOUNCE_INTERVAL) {
//                 self.send_discovery_tm = Some(Instant::now());
// 
//                 let msg = DiscoveryMessage::Announce {local_port: self.local_port, discover_id: self.discover_id, disconnected}.gen_message();
//                 for interface in all_interfaces() {
//                     let ports = once(self.cfg.multicast_port);
//                     let ports = if is_extended_announcement {
//                         ports.chain(self.cfg.multicast_backup_ports.iter().copied())
//                     }
//                     else {
//                         ports.chain([].iter().copied())
//                     };
//                     for port in ports {
//                         if let Err(e) = self.socket.send_to_port(&msg, &Interface::Ip(interface), port) {
//                             warn!("Failed to send discovery message on interface {}: {}", interface, e);
//                         } else {
//                             trace!("Sent discovery message to port {} on interface {}", port, interface);
//                         }
//                     }
//                 }
//             }
//         }
//     }
//     fn try_poll(&mut self) -> Option<PollResult> {
//         // 1. Announce routine
//         self.try_send_announce_packet(false);
// 
//         // 2. Extend request routine
//         if matches!(self.running_port, MulticastRunningPort::Backup(_)) {
//             if self.send_extend_request_tm.is_none_or(|tm| Instant::now() > tm + EXTENDED_ANNOUNCE_REQUEST_INTERVAL) {
//                 self.send_extend_request_tm = Some(Instant::now());
// 
//                 let msg = DiscoveryMessage::ExtendAnnouncements.gen_message();
//                 for interface in all_interfaces() {
//                     let ports = once(self.cfg.multicast_port);
//                     let ports = ports.chain(self.cfg.multicast_backup_ports.iter().copied());
//                     for port in ports {
//                         if let Err(e) = self.socket.send_to_port(&msg, &Interface::Ip(interface), port) {
//                             warn!("Failed to send ExtendAnnouncement message on interface {}: {}", interface, e);
//                         } else {
//                             trace!("Sent discovery message to port {} on interface {}", port, interface);
//                         }
//                     }
//                 }
//             }
// 
//         }
// 
//         // 2. Handle incoming messages
//         if let Ok(Message {
//                       data,
//                       origin_address,
//                       interface
//                   }) = self.socket.receive() {
// 
//             // Shut up messages from ourselves on all interfaces
//             if all_interfaces().contains(&origin_address.ip()) && origin_address.port() == *self.running_port  {
//                 return None;
//             }
// 
//             match DiscoveryMessage::try_parse(&data) {
//                 Some(DiscoveryMessage::Discovery) => {
//                     if self.announce_enabled {
//                         let announce = DiscoveryMessage::Announce {
//                             disconnected: false,
//                             discover_id: self.discover_id,
//                             local_port: self.local_port,
//                         }.gen_message();
//                         if let Err(e) = self.socket.send_to(&announce, origin_address) {
//                             warn!("Failed to answer to discovery packet: {:?}", e);
//                         }
// 
//                     }
//                     None
//                 }
//                 Some(DiscoveryMessage::Announce { local_port, discover_id, disconnected}) => {
//                     if disconnected {
//                         Some(PollResult::DisconnectedClient {
//                             addr: SocketAddrV4::new(
//                                 *origin_address.ip(),
//                                 local_port,
//                             ),
//                             discover_id
//                         })
//                     }
//                     else {
//                         Some(PollResult::DiscoveredClient {
//                             addr: SocketAddrV4::new(
//                                 *origin_address.ip(),
//                                 local_port,
//                             ),
//                             discover_id,
//                         })
//                     }
//                 }
//                 Some(DiscoveryMessage::ExtendAnnouncements) => {
//                     self.extend_disc_request_tm = Some(Instant::now());
// 
//                     None
//                 }
//                 None => {
//                     warn!("Received unknown message from {}: {:?}", origin_address, data);
//                     None
//                 }
//             }
//         }
//         else {
//             None
//         }
//     }
// }
// impl Drop for MulticastDiscoverySocket {
//     fn drop(&mut self) {
//         // Announce disconnection
//         self.try_send_announce_packet(true);
//     }
// }
// fn get_ip_from_ifindex(ifindex: i32) -> Option<Ipv4Addr> {
//     // Iterate through all interfaces
//     for iface in get_if_addrs().ok()? {
//         if iface.index == Some(ifindex as u32) {
//             let IpAddr::V4(ipv4) = iface.ip() else {
//                 return None;
//             };
// 
//             return Some(ipv4);
//         }
//     }
//     None
// }
