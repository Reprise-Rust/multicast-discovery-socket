use std::net::SocketAddrV4;
use sha2::Digest;

/// Message kind for `DiscoveryMessage` type
#[derive(Copy, Clone)]
pub enum DiscoveryMessageKind {
    Discovery,
    Announce,
    ExtendAnnouncements,
}

impl DiscoveryMessageKind {
    fn header(&self) -> &'static [u8] {
        match self {
            DiscoveryMessageKind::Discovery => b"discovery",
            DiscoveryMessageKind::Announce { .. } => b"announce",
            DiscoveryMessageKind::ExtendAnnouncements => b"extend-announcements",
        }
    }
}

#[derive(Copy, Clone)]
pub enum DiscoveryMessage {
    /// Ping packet used to trigger other endpoints to send Announce packet back
    Discovery,
    /// Tell other endpoints that we are running and available for making connection
    Announce {
        local_port: u16,
        discover_id: u32,
        disconnected: bool,
    },
    /// Request for endpoints on Primary and Backup ports to extend their announcements scope to Backup ports as well
    ExtendAnnouncements,
}

impl DiscoveryMessage {
    fn msg_type(&self) -> DiscoveryMessageKind {
        match self {
            DiscoveryMessage::Discovery => DiscoveryMessageKind::Discovery,
            DiscoveryMessage::Announce { .. } => DiscoveryMessageKind::Announce,
            DiscoveryMessage::ExtendAnnouncements => DiscoveryMessageKind::ExtendAnnouncements,
        }
    }
    pub(crate) fn try_parse(msg: &[u8]) -> Option<Self> {
        if msg.starts_with(DiscoveryMessageKind::Discovery.header())
            && msg.len() == DiscoveryMessageKind::Discovery.header().len() + 32
            && msg.ends_with(sha2::Sha256::digest(&msg[..msg.len() - 32]).as_ref()) {
            Some(DiscoveryMessage::Discovery)
        } else if msg.starts_with(DiscoveryMessageKind::Announce.header())
            && msg.len() == DiscoveryMessageKind::Announce.header().len() + 2 + 4 + 32 + 1 {
            let msg_body = &msg[DiscoveryMessageKind::Announce.header().len()..];
            let local_port = u16::from_be_bytes(msg_body[0..2].try_into().unwrap());
            let discover_id = u32::from_be_bytes(msg_body[2..6].try_into().unwrap());
            let disconnected = msg_body[6] != 0;
            let sha = sha2::Sha256::digest(&msg[..msg.len() - 32]);
            if msg.ends_with(&sha[..32]) {
                Some(DiscoveryMessage::Announce { local_port, discover_id, disconnected })
            } else {
                None
            }
        } else if msg.starts_with(DiscoveryMessageKind::ExtendAnnouncements.header())
            && msg.len() == DiscoveryMessageKind::ExtendAnnouncements.header().len() + 32
            && msg.ends_with(sha2::Sha256::digest(&msg[..msg.len() - 32]).as_ref()) {
            Some(DiscoveryMessage::ExtendAnnouncements)
        } else {
            None
        }
    }
    pub(crate) fn gen_message(&self) -> Vec<u8> {
        let header = self.msg_type().header();
        let mut message = match self {
            DiscoveryMessage::Discovery => header.to_vec(),
            DiscoveryMessage::Announce { local_port, discover_id, disconnected } => {
                let mut hello_msg = header.to_vec();
                hello_msg.extend_from_slice(local_port.to_be_bytes().as_ref());
                hello_msg.extend_from_slice(discover_id.to_be_bytes().as_ref());
                hello_msg.push(*disconnected as u8);
                hello_msg
            }
            DiscoveryMessage::ExtendAnnouncements => header.to_vec(),
        };

        let sha = sha2::Sha256::digest(&message);
        message.extend_from_slice(&sha[..32]);
        message
    }
}


pub enum PollResult {
    Nothing,
    DiscoveredClient {
        addr: SocketAddrV4,
        discover_id: u32,
    },
    DisconnectedClient {
        addr: SocketAddrV4,
        discover_id: u32
    }
}