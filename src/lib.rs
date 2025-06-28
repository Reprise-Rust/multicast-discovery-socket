use std::{io, thread};
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

pub struct MulticastDiscoverySocket {
    socket: MultiInterfaceSocket,
    cfg: MulticastDiscoveryConfig,
    discover_id: u32,
    running_port: MulticastRunningPort,
    interface_tracker: InterfaceTracker<PerInterfaceState>,

    announce_enabled: bool,
    discover_replies: bool,
    /// Announce payload: service port. If not set, announcements are disabled
    local_port: Option<u16>,
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

pub enum PollResult {
    DiscoveredClient {
        addr: SocketAddrV4,
        discover_id: u32,
    },
    DisconnectedClient {
        addr: SocketAddrV4,
        discover_id: u32,
    }
}

impl MulticastDiscoverySocket {
    pub fn new_discover_only(cfg: &MulticastDiscoveryConfig) -> io::Result<Self> {
        Self::new(cfg, None)
    }
    /// Create new socket for multicast discovery.
    pub fn new(cfg: &MulticastDiscoveryConfig, local_port: Option<u16>) -> io::Result<Self> {
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
                        local_port,
                        cfg: cfg.clone(),
                        discover_id: rand::random_range(0..u32::MAX),
                        running_port,

                        announce_enabled: cfg.enable_announce,
                        discover_replies: cfg.enable_announce,
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

    /// Manually discover all clients on main or backup ports (using `Discovery` message).
    /// Results can be collected by running `poll`.
    pub fn discover(&mut self) {
        info!("Multicast discovery: running manual discovery...");
        let msg = DiscoveryMessage::Discovery.gen_message();
        for (interface, _) in self.interface_tracker.iter_mut() {
            let Some(index) = interface.index else {
                continue;
            };
            if interface.ip().is_loopback() {
                continue;
            }

            for port in self.cfg.iter_ports() {
                if let Err(e) = self.socket.send_to_iface(&msg, SocketAddrV4::new(self.cfg.multicast_group_ip, port), index) {
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
    pub fn poll(&mut self, mut discover_msg: impl FnMut(PollResult)) {
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
        if self.announce_enabled && self.local_port.is_some() {
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
                        local_port: self.local_port.unwrap_or_default(),
                        discover_id: self.discover_id,
                        disconnected: false
                    }.gen_message();
                    if should_extended_announce {
                        for port in self.cfg.iter_ports() {
                            let res = self.socket.send_to_iface(&msg, SocketAddrV4::new(self.cfg.multicast_group_ip, port), interface_index);
                            handle_err(res, "send extended announce", interface);
                        }
                    }
                    else {
                        let res = self.socket.send_to_iface(&msg, SocketAddrV4::new(self.cfg.multicast_group_ip, self.cfg.multicast_port), interface_index);
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
                    let msg = DiscoveryMessage::ExtendAnnouncements.gen_message();
                    for port in self.cfg.iter_ports() {
                        let res = self.socket.send_to_iface(&msg, SocketAddrV4::new(self.cfg.multicast_group_ip, port), interface_index);
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

        // 3. Handle incoming packets
        let mut buf = [0u8;256];
        while let Ok((data, addr, index)) = self.socket.recv_from_iface(&mut buf) {

            // Shut up messages from ourselves on all interfaces
            if self.interface_tracker.iter_mut().any(|(i, _)| i.ip() == IpAddr::V4(*addr.ip())) && addr.port() == *self.running_port {
                continue;
            }

            match DiscoveryMessage::try_parse(&data) {
                Some(DiscoveryMessage::Discovery) => {
                    if self.discover_replies && self.local_port.is_some() {
                        let announce = DiscoveryMessage::Announce {
                            disconnected: false,
                            discover_id: self.discover_id,
                            local_port: self.local_port.unwrap_or_default(),
                        }.gen_message();
                        if let Err(e) = self.socket.send_to_iface(&announce, addr, index) {
                            warn!("Failed to answer to discovery packet: {:?}", e);
                        }

                    }
                }
                Some(DiscoveryMessage::Announce { local_port, discover_id, disconnected}) => {
                    if disconnected {
                        discover_msg(PollResult::DisconnectedClient {
                            addr: SocketAddrV4::new(
                                *addr.ip(),
                                local_port,
                            ),
                            discover_id
                        })
                    }
                    else {
                        discover_msg(PollResult::DiscoveredClient {
                            addr: SocketAddrV4::new(
                                *addr.ip(),
                                local_port,
                            ),
                            discover_id,
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
impl Drop for MulticastDiscoverySocket {
    fn drop(&mut self) {
        // Announce disconnection
        if self.announce_enabled && self.local_port.is_some() {
            for (interface, state) in self.interface_tracker.iter_mut() {
                let Some(index) = interface.index else {
                    continue;
                };
                // Skip for now
                if interface.ip().is_loopback() {
                    continue;
                }

                let msg = DiscoveryMessage::Announce {
                    discover_id: self.discover_id,
                    local_port: self.local_port.unwrap_or_default(),
                    disconnected: true
                }.gen_message();
                for port in self.cfg.iter_ports() {
                    let res = self.socket.send_to_iface(&msg, SocketAddrV4::new(self.cfg.multicast_group_ip, port),index);
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
