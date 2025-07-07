use std::iter;
use std::net::{IpAddr, Ipv4Addr};

/// \[fallback\]
/// Fallback implementation: represents interface with ip address 0.0.0.0
#[derive(PartialEq, Eq, Hash, Clone)]
pub struct Interface {
    /// \[fallback\]
    /// Equals to "fallback-interface"
    pub name: String,
    /// \[fallback\]
    /// Equals to Some(1)
    pub index: Option<u32>
}

impl Default for Interface {
    fn default() -> Self {
        Self {
            name: String::from("fallback-interface"),
            index: Some(1),
        }
    }
}

impl Interface {
    pub fn ip(&self) -> IpAddr {
        Ipv4Addr::UNSPECIFIED.into()
    }
}

/// \[fallback\]
/// Always returns a single interface with index 1 and ip address 0.0.0.0
pub struct InterfaceTracker<D> {
    data: D,
    interface: Interface,
}
impl<D: Default> InterfaceTracker<D> {
    /// \[fallback\]
    /// Always returns a single interface with index 1 and ip address 0.0.0.0
    pub fn new() -> Self {
        Self {
            data: D::default(),
            interface: Interface::default(),
        }
    }

    /// \[fallback\]
    /// Always returns a single interface with index 1 and ip address 0.0.0.0
    pub fn iter_mut(&mut self) -> impl Iterator<Item=(&Interface, &mut D)> {
        iter::once((&self.interface, &mut self.data))
    }

    /// Iterate through index-ip_address pairs. The same index may be paired with multiple ip addresses!
    ///
    /// \[fallback\]
    /// Always returns a single interface with index 1 and ip address 0.0.0.0
    pub fn iter_mapping(&self) -> impl Iterator<Item=(u32, Ipv4Addr)> {
        iter::once((1, Ipv4Addr::UNSPECIFIED))
    }

    /// \[fallback\]
    /// Always returns a single interface with index 1 and ip address 0.0.0.0
    /// `on_new_ip` is never called in this implementation
    pub fn poll_updates(&mut self, mut on_new_ip: impl FnMut(Ipv4Addr)) {

    }
}
