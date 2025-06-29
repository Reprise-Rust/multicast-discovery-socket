use std::net::Ipv4Addr;
use std::sync::atomic::AtomicBool;
use std::thread;
use std::time::{Duration, Instant};
use log::info;
use multicast_discovery_socket::config::MulticastDiscoveryConfig;
use multicast_discovery_socket::{MulticastDiscoverySocket, PollResult};

fn main() {
    simple_logger::init_with_level(log::Level::Debug).unwrap();

    static EXIT: AtomicBool = AtomicBool::new(false);
    ctrlc::set_handler(|| {
        EXIT.store(true, std::sync::atomic::Ordering::Relaxed);
    }).unwrap();

    let cfg = MulticastDiscoveryConfig::new(Ipv4Addr::new(239, 37, 37, 37), "multicast-example".into())
        .with_multicast_port(37337)
        .with_backup_ports(62337..62339);
    let mut socket: MulticastDiscoverySocket<()> = MulticastDiscoverySocket::new_discover_only(&cfg).unwrap();

    let mut last_send_tm: Option<Instant> = None;
    loop {
        if last_send_tm.is_none_or(|tm| tm.elapsed() > Duration::from_secs(10)) {
            info!("Sending manual discovery message");
            socket.discover();
            last_send_tm = Some(Instant::now());
        }
        if EXIT.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        socket.poll(|msg| {
            match msg {
                PollResult::DiscoveredClient {
                    addr,
                    discover_id,
                    adv_data
                } => {
                    println!("Discovered client: {} - {:x}", addr, discover_id);
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
}