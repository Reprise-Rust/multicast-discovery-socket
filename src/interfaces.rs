use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use log::info;

pub use if_addrs::Interface;

pub struct InterfaceTracker<D> {
    interfaces: HashMap<Ipv4Addr, (Interface, D)>,
}

impl<D: Default> InterfaceTracker<D> {
    pub fn new() -> Self {
        Self {
            interfaces: get_ipv4_interfaces()
                .map(|i| (i.0, (i.1, D::default())))
                .collect(),
        }
    }
    pub fn iter_mut(&mut self) -> impl Iterator<Item=(&Interface, &mut D)> {
        self.interfaces.values_mut()
            .map(|(i, d)| (&*i, d))
    }
    
    /// Iterate through index-ip_address pairs. The same index may be paired with multiple ip addresses!
    pub fn iter_mapping(&self) -> impl Iterator<Item=(u32, Ipv4Addr)> {
        self.interfaces.iter()
            .filter_map(|(ip, i)| i.0.index.map(|i| (i, *ip)))
    }
    
    pub fn poll_updates(&mut self, mut on_new_ip: impl FnMut(Ipv4Addr)) {
        let mut original_ips: Vec<Ipv4Addr> = self.interfaces.keys().cloned().collect();
        for (new_ip, new_interface) in get_ipv4_interfaces() {
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

fn get_ipv4_interfaces() -> impl Iterator<Item=(Ipv4Addr, Interface)> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|i| {
            if let IpAddr::V4(ip) = &i.ip() {
                if ip.is_private() {
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