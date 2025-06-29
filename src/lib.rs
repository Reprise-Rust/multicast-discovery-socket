#![allow(clippy::int_plus_one)]
#![allow(clippy::new_without_default)]

use std::{io, thread};
use std::borrow::Cow;
use std::iter::once;
use std::net::{IpAddr, SocketAddrV4};
use std::ops::Deref;
use std::time::{Duration, Instant};
use if_addrs::Interface;
use log::{debug, error, info, warn};
use crate::config::MulticastDiscoveryConfig;
use crate::interfaces::InterfaceTracker;
use crate::protocol::DiscoveryMessage;
use crate::socket::MultiInterfaceSocket;

pub mod config;
pub mod protocol;
pub mod socket;
pub mod interfaces;

#[derive(Default)]
pub struct PerInterfaceState {
    last_announce_tm: Option<Instant>,
    extended_announcements_request_tm: Option<Instant>,
    extend_request_send_tm: Option<Instant>,

    extended_announce_enabled: bool,
}

impl PerInterfaceState {
    pub fn should_announce(&self, now: Instant, cfg: &MulticastDiscoveryConfig) -> bool {
        self.last_announce_tm.is_none_or(|tm| now - tm > cfg.announce_interval)
    }
    pub fn should_send_extend_request(&self, now: Instant, cfg: &MulticastDiscoveryConfig) -> bool {
        self.extend_request_send_tm.is_none_or(|tm| now - tm > cfg.extend_request_interval)
    }
    pub fn should_extended_announce(&self, now: Instant, cfg: &MulticastDiscoveryConfig) -> bool {
        self.extended_announcements_enabled(now, cfg) && self.should_announce(now, cfg)
    }

    pub fn extended_announcements_enabled(&self, now: Instant, cfg: &MulticastDiscoveryConfig) -> bool {
        self.extended_announcements_request_tm.is_some_and(|tm| now - tm < cfg.extended_announcement_effect_dur)
    }
    pub fn got_extend_announce_req(&mut self, now: Instant) {
        self.extended_announcements_request_tm = Some(now);
        self.extended_announce_enabled = true;
    }
}

pub trait AdvertisementData: Sized + Clone {
    fn encode_to_bytes(&self) -> Vec<u8>;
    fn try_decode(bytes: &[u8]) -> Option<Self>;
}
#[cfg(not(feature="bincode"))]
mod adv_data_impls {
    use super::AdvertisementData;
    impl AdvertisementData for () {
        fn encode_to_bytes(&self) -> Vec<u8> {
            Vec::new()
        }
        fn try_decode(bytes: &[u8]) -> Option<Self> {
            if bytes.is_empty() {
                Some(())
            }
            else {
                None
            }
        }

    }
    impl AdvertisementData for Vec<u8> {
        fn encode_to_bytes(&self) -> Vec<u8> {
            self.clone()
        }
        fn try_decode(bytes: &[u8]) -> Option<Self> {
            Some(bytes.to_vec())
        }
    }
}

#[cfg(feature="bincode")]
use bincode::{Decode, Encode};
#[cfg(feature="bincode")]
impl<T> AdvertisementData for T
    where T: Encode + Decode<()> + Clone {
    fn encode_to_bytes(&self) -> Vec<u8> {
        bincode::encode_to_vec(self, bincode::config::standard()).unwrap()
    }
    fn try_decode(bytes: &[u8]) -> Option<Self> {
        bincode::decode_from_slice(bytes, bincode::config::standard())
            .ok()
            .map(|(v, _)| v)
    }
}

pub struct MulticastDiscoverySocket<D: AdvertisementData> {
    socket: MultiInterfaceSocket,
    cfg: MulticastDiscoveryConfig,
    discover_id: u32,
    running_port: MulticastRunningPort,
    interface_tracker: InterfaceTracker<PerInterfaceState>,

    announce_enabled: bool,
    discover_replies: bool,
    /// Announce payload: service port. If not set, announcements are disabled
    service_port_and_adv_data: Option<(u16, D)>,
}

#[derive(Debug, Copy, Clone)]
pub enum MulticastRunningPort {
    Primary(u16),
    Backup(u16),
    Other
}

impl Deref for MulticastRunningPort {
    type Target = u16;
    fn deref(&self) -> &Self::Target {
        match self {
            MulticastRunningPort::Primary(p) => p,
            MulticastRunningPort::Backup(p) => p,
            MulticastRunningPort::Other => &0,
        }
    }
}


pub enum PollResult<'a, D> {
    DiscoveredClient {
        addr: SocketAddrV4,
        discover_id: u32,
        adv_data: &'a D,
    },
    DisconnectedClient {
        addr: SocketAddrV4,
        discover_id: u32
    }
}

impl<D: AdvertisementData> MulticastDiscoverySocket<D> {
    /// Create new socket for multicast discovery. Announcements are disabled (running without service)
    /// Enable feature `bincode` for passing `Encode` + `Decode` types as adv_data
    pub fn new_discover_only(cfg: &MulticastDiscoveryConfig) -> io::Result<Self> {
        Self::new(cfg, None)
    }
    /// Create new socket for multicast discovery. Announcements are enabled depending on config.
    /// Enable feature `bincode` for passing `Encode` + `Decode` types as adv_data
    pub fn new_with_service(cfg: &MulticastDiscoveryConfig, service_port: u16, initial_adv_data: D) -> io::Result<Self> {
        Self::new(cfg, Some((service_port, initial_adv_data)))
    }
    fn new(cfg: &MulticastDiscoveryConfig, service_port_and_adv_data: Option<(u16, D)>) -> io::Result<Self> {
        let central_discovery_enabled = cfg.central_discovery_addr.is_some();
        let mut is_primary = true;
        
        let mut interface_tracker = InterfaceTracker::new();
        // Try primary and backup ports
        let main_port = cfg.iter_ports().next().unwrap();
        for port in cfg.iter_ports().chain(once(0)) {
            match MultiInterfaceSocket::bind_port(port) {
                Ok(socket) => {
                    // Join multicast group on all interfaces
                    for (interface, _) in interface_tracker.iter_mut() {
                        if let IpAddr::V4(ip) = interface.ip() {
                            if let Err(e) = socket.join_multicast_group(cfg.multicast_group_ip, ip) {
                                warn!("Failed to join multicast group on interface {}: {}", interface.ip(), e);
                            }
                            else {
                                info!("Joined multicast group on interface {}", interface.ip());
                            }
                        }
                    }
                   
                    // Set non-blocking
                    socket.set_nonblocking(true)?;
                    
                    let running_port = if is_primary {
                        debug!("Using primary multicast port {} for discovery", port);
                        MulticastRunningPort::Primary(port)
                    }
                    else if port == 0 {
                        let failed_ports = cfg.iter_ports().filter(|p| *p != 0);
                        warn!("Unable to start on the main or backup ports ({:?})!", &failed_ports.collect::<Vec<_>>());
                        if !central_discovery_enabled {
                            warn!("You may face issues with discovering");
                        }
                        else {
                            warn!("You will be able to discover clients only when your network is online!");
                        }
                        MulticastRunningPort::Other
                    }
                    else {
                        warn!("Using backup multicast port {} for discovery (unable to start on main port {})", port, main_port);
                        MulticastRunningPort::Backup(port)
                    };
                    return Ok(Self {
                        socket,
                        interface_tracker,
                        cfg: cfg.clone(),
                        discover_id: rand::random_range(0..u32::MAX),
                        running_port,

                        announce_enabled: cfg.enable_announce,
                        discover_replies: cfg.enable_announce,

                        service_port_and_adv_data,
                    })
                }
                Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
                    is_primary = false;
                    continue
                },
                Err(e) => {
                    is_primary = false;
                    warn!("Failed to bind socket to port {}: {}", port, e);
                    continue;
                }
            }
        }
    
        error!("Failed to bind multicast discovery socket to any port!");
        Err(io::Error::new(io::ErrorKind::AddrInUse, "Failed to bind socket to any port"))
    }
    
    pub fn discover_id(&self) -> u32 {
        self.discover_id
    }
    pub fn running_port(&self) -> MulticastRunningPort {
        self.running_port
    }

    /// Setting this to `false` will disable periodic background announcements during `poll()`
    /// Announcements are performed by periodic sending message `Announce` (and `ExtendAnnounce`)
    pub fn set_announce_en(&mut self, en: bool) {
        self.announce_enabled = en;
    }

    /// Setting this to `false` will disable automatic replies to `Discovery` messages
    pub fn set_discover_replies_en(&mut self, enable: bool) {
        self.discover_replies = enable;
    }

    /// Guaranteed to return Some(&mut D) if was created with `Self::new`
    pub fn adv_data(&mut self) -> Option<&mut D> {
        self.service_port_and_adv_data.as_mut().map(|s| &mut s.1)
    }

    /// Manually discover all clients on main or backup ports (using `Discovery` message).
    /// Results can be collected by running `poll`.
    pub fn discover(&mut self) {
        info!("Multicast discovery: running manual discovery...");
        let msg = DiscoveryMessage::Discovery::<D>.gen_message();
        for (interface, _) in self.interface_tracker.iter_mut() {
            let Some(index) = interface.index else {
                continue;
            };
            if interface.ip().is_loopback() {
                continue;
            }

            for port in self.cfg.iter_ports() {
                if let Err(e) = self.socket.send_to_iface(&msg, SocketAddrV4::new(self.cfg.multicast_group_ip, port), index, interface.addr.ip()) {
                    warn!("Failed to send discovery message on interface [{}] - {}: {}", interface.ip(), interface.name, e);
                } else {
                    debug!("Sent discovery message to port {} on interface [{}] - {}", port, interface.ip(), interface.name);
                }
            }
        }
    }

    /// Run `poll` periodically to handle internal discovery mechanisms:
    /// - `Announce` messages periodic sending
    /// - `ExtendAnnounce` messages periodic sending (if running on backup port)
    /// - handling incoming messages (and returning discovery results via `discover_msg` callback)
    ///
    /// It is recommended to call this function in a loop with ~100ms sleep
    pub fn poll(&mut self, mut discover_msg: impl FnMut(PollResult<D>)) {
        // 0. poll interface updates
        self.interface_tracker.poll_updates(|new_ip| {
            if let Err(e) = self.socket.join_multicast_group(self.cfg.multicast_group_ip, new_ip) {
                warn!("Failed to join multicast group on interface {}: {}", new_ip, e);
            }
            else {
                info!("Joined multicast group on interface {}!", new_ip);
            }
        });
    
        let mut interface_cnt = 0;
        if let Some((service_port, adv_data)) = self.service_port_and_adv_data.as_mut() {
            if self.announce_enabled {
                for (interface, state) in self.interface_tracker.iter_mut() {
                    let Some(interface_index) = interface.index else {
                        continue;
                    };
                    // Skip for now
                    if interface.ip().is_loopback() {
                        continue;
                    }

                    // 1. Handle announcements
                    let now = Instant::now();
                    let should_announce = state.should_announce(now, &self.cfg);
                    let should_extended_announce = state.should_extended_announce(now, &self.cfg);
                    let should_send_extend_request = state.should_send_extend_request(now, &self.cfg);
                    if should_announce {
                        state.last_announce_tm = Some(now);

                        let msg = DiscoveryMessage::Announce {
                            service_port: *service_port,
                            discover_id: self.discover_id,
                            disconnected: false,
                            adv_data: Cow::Borrowed(&*adv_data)
                        }.gen_message();
                        if should_extended_announce {
                            for port in self.cfg.iter_ports() {
                                let res = self.socket.send_to_iface(&msg, SocketAddrV4::new(self.cfg.multicast_group_ip, port), interface_index, interface.addr.ip());
                                handle_err(res, "send extended announce", interface);
                            }
                        }
                        else {
                            let res = self.socket.send_to_iface(&msg, SocketAddrV4::new(self.cfg.multicast_group_ip, self.cfg.multicast_port), interface_index, interface.addr.ip());
                            handle_err(res, "send normal announce", interface);
                        }
                        if state.extended_announce_enabled && !state.extended_announcements_enabled(now, &self.cfg) {
                            state.extended_announce_enabled = false;
                            info!("No longer sending extended announce on interface [{}] - {}", interface.ip(), interface.name);
                        }
                    }
                    // 2. Sending extend requests
                    if matches!(self.running_port, MulticastRunningPort::Backup(_)) && should_send_extend_request {
                        state.extend_request_send_tm = Some(now);
                        let msg = DiscoveryMessage::ExtendAnnouncements::<D>.gen_message();
                        for port in self.cfg.iter_ports() {
                            let res = self.socket.send_to_iface(&msg, SocketAddrV4::new(self.cfg.multicast_group_ip, port), interface_index, interface.addr.ip());
                            handle_err(res, "send extended announce request", interface);
                        }
                    }
                    interface_cnt += 1;
                }

                if interface_cnt == 0 {
                    warn!("No available interface found!");
                    thread::sleep(Duration::from_millis(500));
                }
            }
        }

        // 3. Handle incoming packets
        let mut buf = [0u8;256];
        while let Ok((data, addr, index)) = self.socket.recv_from_iface(&mut buf) {

            // Shut up messages from ourselves on all interfaces
            if self.interface_tracker.iter_mut().any(|(i, _)| i.ip() == IpAddr::V4(*addr.ip())) && addr.port() == *self.running_port {
                continue;
            }

            match DiscoveryMessage::<D>::try_parse(data) {
                Some(DiscoveryMessage::Discovery) => {
                    if let Some((service_port, adv_data)) = self.service_port_and_adv_data.as_mut() {
                        if self.discover_replies {
                            let announce = DiscoveryMessage::Announce {
                                disconnected: false,
                                discover_id: self.discover_id,
                                service_port: *service_port,
                                adv_data: Cow::Borrowed(&*adv_data)
                            }.gen_message();
                            let source_addr = self.interface_tracker.iter_mapping().find(|(i, _)| *i == index);
                            if let Some((_, a)) = source_addr {
                                if let Err(e) = self.socket.send_to_iface(&announce, addr, index, a.into()) {
                                    warn!("Failed to answer to discovery packet: {:?}", e);
                                }
                            }
                            else {
                                warn!("Failed to answer discovery packet: interface address not found for index!");
                            }
                        }
                    }
                }
                Some(DiscoveryMessage::Announce { service_port, discover_id, disconnected, adv_data}) => {
                    if disconnected {
                        discover_msg(PollResult::DisconnectedClient {
                            addr: SocketAddrV4::new(
                                *addr.ip(),
                                service_port,
                            ),
                            discover_id
                        })
                    }
                    else {
                        discover_msg(PollResult::DiscoveredClient {
                            addr: SocketAddrV4::new(
                                *addr.ip(),
                                service_port,
                            ),
                            discover_id,
                            adv_data: adv_data.as_ref(),
                        })
                    }
                }
                Some(DiscoveryMessage::ExtendAnnouncements) => {
                    for (interface, state) in self.interface_tracker.iter_mut() {
                        if interface.index == Some(index) {
                            let now = Instant::now();
                            if !state.extended_announcements_enabled(now, &self.cfg) {
                                info!("Enabling extended announcements on interface [{}] - {}", interface.ip(), interface.name);
                            }
                            state.got_extend_announce_req(now);
                        }
                    }
                }
                None => {
                    warn!("Received unknown message from {}: {:?}", addr, data);
                }
            }
        }
    }
}
impl<D: AdvertisementData> Drop for MulticastDiscoverySocket<D> {
    fn drop(&mut self) {
        // Announce disconnection
        if !self.announce_enabled {
            return;
        }
        if let Some((service_port, adv_data)) = self.service_port_and_adv_data.as_ref() {
            for (interface, _) in self.interface_tracker.iter_mut() {
                let Some(index) = interface.index else {
                    continue;
                };
                // Skip for now
                if interface.ip().is_loopback() {
                    continue;
                }

                let msg = DiscoveryMessage::Announce {
                    discover_id: self.discover_id,
                    service_port: *service_port,
                    disconnected: true,
                    adv_data: Cow::Borrowed(adv_data)
                }.gen_message();
                for port in self.cfg.iter_ports() {
                    let res = self.socket.send_to_iface(&msg, SocketAddrV4::new(self.cfg.multicast_group_ip, port),index, interface.addr.ip());
                    handle_err(res, "announce disconnected message", interface);
                }
            }
        }
    }
}

fn handle_err(result: io::Result<usize>, msg: &'static str, interface: &Interface) {
    if let Err(e) = result {
        warn!("Failed to {} on interface [{:?}] - {}: {}", msg, interface.ip(), interface.name, e);
    }
}
