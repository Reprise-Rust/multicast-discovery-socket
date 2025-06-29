use std::borrow::Cow;
use log::debug;
use sha2::Digest;
use crate::AdvertisementData;

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
            DiscoveryMessageKind::Announce => b"announce",
            DiscoveryMessageKind::ExtendAnnouncements => b"extend-announcements",
        }
    }
}

#[derive(Clone)]
pub enum DiscoveryMessage<'a, D: AdvertisementData> {
    /// Ping packet used to trigger other endpoints to send Announce packet back
    Discovery,
    /// Tell other endpoints that we are running and available for making connection
    Announce {
        service_port: u16,
        discover_id: u32,
        disconnected: bool,
        adv_data: Cow<'a, D>,
    },
    /// Request for endpoints on Primary and Backup ports to extend their announcements scope to Backup ports as well
    ExtendAnnouncements,
}

impl<D: AdvertisementData> DiscoveryMessage<'_, D> {
    fn msg_type(&self) -> DiscoveryMessageKind {
        match self {
            DiscoveryMessage::Discovery => DiscoveryMessageKind::Discovery,
            DiscoveryMessage::Announce { .. } => DiscoveryMessageKind::Announce,
            DiscoveryMessage::ExtendAnnouncements => DiscoveryMessageKind::ExtendAnnouncements,
        }
    }
    pub(crate) fn try_parse(msg: &[u8]) -> Option<Self> {
        if msg.len() < 32 + 1 {
            debug!("Packet is too small, ignoring...");
            return None;
        }
        let msg_len = msg.len() - 32;
        let sha = sha2::Sha256::digest(&msg[..msg_len]);
        if !msg.ends_with(&sha[..32]) {
            debug!("Incorrect sha2, ignoring message...");
            return None;
        }
        if msg.starts_with(DiscoveryMessageKind::Discovery.header())
            && msg_len == DiscoveryMessageKind::Discovery.header().len() {
            Some(DiscoveryMessage::Discovery)
        } else if msg.starts_with(DiscoveryMessageKind::Announce.header())
            && msg_len >= DiscoveryMessageKind::Announce.header().len() + 2 + 4 + 1 {
            let msg_body = &msg[DiscoveryMessageKind::Announce.header().len()..msg_len];
            let service_port = u16::from_be_bytes(msg_body[0..2].try_into().unwrap());
            let discover_id = u32::from_be_bytes(msg_body[2..6].try_into().unwrap());
            let disconnected = msg_body[6] != 0;
            let adv_data_body = &msg_body[7..];
            let adv_data = D::try_decode(adv_data_body)?;

            Some(DiscoveryMessage::Announce {
                adv_data: Cow::Owned(adv_data),
                service_port,
                disconnected,
                discover_id
            })
        } else if msg.starts_with(DiscoveryMessageKind::ExtendAnnouncements.header())
            && msg_len == DiscoveryMessageKind::ExtendAnnouncements.header().len() {
            Some(DiscoveryMessage::ExtendAnnouncements)
        } else {
            None
        }
    }
    pub(crate) fn gen_message(&self) -> Vec<u8> {
        let header = self.msg_type().header();
        let mut message = match self {
            DiscoveryMessage::Discovery => header.to_vec(),
            DiscoveryMessage::Announce { service_port, discover_id, disconnected, adv_data } => {
                let mut hello_msg = header.to_vec();
                hello_msg.extend_from_slice(service_port.to_be_bytes().as_ref());
                hello_msg.extend_from_slice(discover_id.to_be_bytes().as_ref());
                hello_msg.push(*disconnected as u8);
                hello_msg.extend_from_slice(&adv_data.encode_to_bytes());
                hello_msg
            }
            DiscoveryMessage::ExtendAnnouncements => header.to_vec(),
        };

        let sha = sha2::Sha256::digest(&message);
        message.extend_from_slice(&sha[..32]);
        message
    }
}
