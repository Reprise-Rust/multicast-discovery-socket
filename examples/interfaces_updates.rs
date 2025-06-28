use std::thread;
use std::time::Duration;
use multicast_discovery_socket::interfaces::InterfaceTracker;

pub fn main() {
    simple_logger::init_with_level(log::Level::Info).unwrap();

    
    let mut interface_tracker = InterfaceTracker::<()>::new();
    println!("IPv4 interfaces list:");
    for (interface, _) in interface_tracker.iter_mut() {
        println!("{:#?}", interface);
    }
    loop {
        thread::sleep(Duration::from_millis(100));
        interface_tracker.poll_updates(|_| {
        });
    }
}