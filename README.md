# Multicast discovery socket

[![crate][crate-image]][crate-link]
![Apache2/MIT licensed][license-image]
![MSRV][rustc-image]

Integrate local client discovery into your rust application with ease!

## About

**What can it do?**
- Continuously discover local clients AND announce yourself to local networks
- Hot-change interface detection: automatically detects added/changed network interfaces for stable discovery
- Support multiple instances on the same host: each application can discover both applications on the same host and on other hosts
- Keep multicast traffic low: load is proportional to the number of applications on a certain interface (by default 1 UDP packet per 2 seconds)
- Support multiple ports: built-in support for backup ports for discovery if main port is not available
- Service port: announcements includes a service port for main communication, making your application independent on bound port
- Custom advertisement data: any type implementing `bincode::Encode` + `bincode::Decode<()>` + Clone

**What it cannot do?**
- No support for IPv6. IPv4 is supported only.
- Work without multicast support. Multicast is required for discovery.


## ⚠️ Work in progress
This library works well as a proof of concept, but it is not yet tested enough.
You can use it, but you cannot totally rely on it (yet)

## Usage
Check the `discovery` example. Run multiple instances of it on the same host/network and see how they discover each other.
```rust
let cfg = MulticastDiscoveryConfig::new(Ipv4Addr::new(239, 37, 37, 37), "multicast-example".into())
    .with_multicast_port(37337)
    .with_backup_ports(62337..62339);

let name = format!("Client {}", rand::random::<u8>());
info!("Running as {name}");
let mut socket = MulticastDiscoverySocket::new(&cfg, Some(12345), name).unwrap();

loop {
    socket.poll(|msg| {
        match msg {
            PollResult::DiscoveredClient {
                addr,
                discover_id,
                adv_data
            } => {
                println!("Discovered client: {} - {:x}: {:?}", addr, discover_id, adv_data);
            }
            PollResult::DisconnectedClient {
                addr,
                discover_id
            } => {
                println!("Disconnected client: {} - {:x}", addr, discover_id);
            }
        }
    });
    thread::sleep(Duration::from_millis(100));
}
```

## License

Licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## References
Support for multiple interfaces is hard to be implemented in cross-platform way.  
Windows and Linux support is implemented mostly relying on code from [multicast-socket](https://crates.io/crates/multicast-socket)  
Thanks to [Bruno Tavares](https://github.com/bltavares) for his work and research on multicast support!