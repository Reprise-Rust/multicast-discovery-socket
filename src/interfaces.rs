use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use log::info;

pub use if_addrs::Interface;

const DEFAULT_IGNORED_PREFIXES: &[&str] = &[
    "cni",
    "flannel.",
    "veth",
    "docker",
    "br-",
    "virbr",
    "tun",
    "tap",
    "cali",
    "weave",
    "kube-",
];

/// Default filter: excludes common tunnel/virtual/docker interface names.
fn default_filter(interface: &Interface) -> bool {
    !DEFAULT_IGNORED_PREFIXES
        .iter()
        .any(|prefix| interface.name.starts_with(prefix))
}

pub struct InterfaceTracker<D> {
    interfaces: HashMap<Ipv4Addr, (Interface, D)>,
    filters: Vec<Box<dyn Fn(&Interface) -> bool>>,
}

impl<D: Default> Default for InterfaceTracker<D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: Default> InterfaceTracker<D> {
    /// Uses the default filter (excludes virtual/docker/overlay interfaces).
    pub fn new() -> Self {
        Self::with_filters(vec![Box::new(default_filter)])
    }

    /// Tracks all private IPv4 interfaces without any name filtering.
    pub fn new_without_filter() -> Self {
        Self::with_filters(Vec::new())
    }

    /// Uses the default filter plus `filter`, i.e. an interface is tracked only if it
    /// passes both. The custom filter can therefore only narrow the set, never widen it.
    /// Filters are applied on the initial scan and on every refresh.
    pub fn new_with_filter(filter: impl Fn(&Interface) -> bool + 'static) -> Self {
        Self::with_filters(vec![Box::new(default_filter), Box::new(filter)])
    }

    fn with_filters(filters: Vec<Box<dyn Fn(&Interface) -> bool>>) -> Self {
        let interfaces = get_ipv4_interfaces(&filters)
            .map(|i| (i.0, (i.1, D::default())))
            .collect();
        Self {
            interfaces,
            filters,
        }
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item=(&Interface, &mut D)> {
        self.interfaces.values_mut()
            .map(|(i, d)| (&*i, &mut *d))
    }

    /// Iterate over `(index, ip_address)` pairs. The same index may be paired with multiple ip addresses!
    pub fn iter_mapping(&self) -> impl Iterator<Item=(u32, Ipv4Addr)> {
        self.interfaces.iter()
            .filter_map(|(ip, i)| i.0.index.map(|i| (i, *ip)))
    }

    pub fn poll_updates(&mut self, mut on_new_ip: impl FnMut(Ipv4Addr)) {
        let mut original_ips: Vec<Ipv4Addr> = self.interfaces.keys().cloned().collect();
        for (new_ip, new_interface) in get_ipv4_interfaces(&self.filters) {
            if let Some(pos) = original_ips.iter().position(|x| *x == new_ip) {
                original_ips.swap_remove(pos);
            }
            if let Some((interface, _)) = self.interfaces.get_mut(&new_ip) {
                if interface != &new_interface {
                    if interface.name != new_interface.name {
                        info!("[{:?}] Interface name updated: {:?} -> {:?}", new_ip, interface.name, new_interface.name);
                    }
                    if interface.index != new_interface.index {
                        info!("[{:?}] Interface index updated: {:?} -> {:?}", new_ip, interface.index, new_interface.index);
                    }
                    *interface = new_interface;
                }
            }
            else {
                info!("New interface added: [{:?}] - {}", new_interface.ip(), new_interface.name);
                on_new_ip(new_ip);
                self.interfaces.insert(new_ip, (new_interface, D::default()));
            }
        }

        for interface in original_ips {
            info!("Interface removed: [{interface:?}]");
            self.interfaces.remove(&interface);
        }
    }
}

fn get_ipv4_interfaces(filters: &[Box<dyn Fn(&Interface) -> bool>]) -> impl Iterator<Item=(Ipv4Addr, Interface)> + '_ {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter_map(move |i| {
            if let IpAddr::V4(ip) = &i.ip() {
                if ip.is_private() && filters.iter().all(|f| f(&i)) {
                    Some((*ip, i))
                }
                else {
                    None
                }
            }
            else {
                None
            }
        })
}
