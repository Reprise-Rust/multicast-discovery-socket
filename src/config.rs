use std::borrow::Cow;
use std::iter::once;
use std::net::IpAddr;
use std::ops::Range;
use std::time::Duration;

const DEFAULT_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(3);
const DEFAULT_EXTENDED_ANNOUNCEMENT_EFFECT_DUR: Duration = Duration::from_secs(30);
const DEFAULT_EXTEND_REQUEST_INTERVAL: Duration = Duration::from_secs(12);

#[derive(Clone, Debug)]
pub struct MulticastDiscoveryConfig {
    pub multicast_group_ip: std::net::Ipv4Addr,
    pub multicast_port: u16,
    pub multicast_backup_ports: Vec<u16>,
    pub service_name: Cow<'static, str>,
    pub central_discovery_addr: Option<IpAddr>,

    pub announce_interval: Duration,
    pub extended_announcement_effect_dur: Duration,
    pub extend_request_interval: Duration,
    
    pub enable_announce: bool
}

impl MulticastDiscoveryConfig {
    pub fn new(
        multicast_group_ip: std::net::Ipv4Addr,
        service_name: Cow<'static, str>
    ) -> Self {
        Self {
            multicast_group_ip,
            multicast_port: 37337,
            multicast_backup_ports: (61345..61347).collect(),
            service_name,
            central_discovery_addr: None,
            enable_announce: true,
            
            announce_interval: DEFAULT_ANNOUNCE_INTERVAL,
            extended_announcement_effect_dur: DEFAULT_EXTENDED_ANNOUNCEMENT_EFFECT_DUR,
            extend_request_interval: DEFAULT_EXTEND_REQUEST_INTERVAL,
        }
    }
    
    pub fn with_multicast_port(mut self, multicast_port: u16) -> Self {
        self.multicast_port = multicast_port;
        self
    }
    
    pub fn with_backup_ports(mut self, backup_ports: Range<u16>) -> Self {
        self.multicast_backup_ports = backup_ports.collect();
        self
    }
    
    pub fn iter_ports(&self) -> impl Iterator<Item = u16> + '_ {
        once(self.multicast_port).chain(self.multicast_backup_ports.iter().copied())
    }
    
    pub fn with_disabled_announce(mut self) -> Self {
        self.enable_announce = false;
        self
    }
    
    pub fn with_announce_interval(mut self, announce_interval: Duration) -> Self {
        self.announce_interval = announce_interval;
        self
    }
    
    pub fn with_extended_announcement_effect_dur(mut self, effect_duration: Duration) -> Self {
        self.extended_announcement_effect_dur = effect_duration;
        self
    }
    
    pub fn with_extend_request_interval(mut self, extend_request_interval: Duration) -> Self {
        self.extend_request_interval = extend_request_interval;
        self
    }
}