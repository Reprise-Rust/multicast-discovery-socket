use std::borrow::Cow;
use log::debug;
use sha2_const_stable::Sha256;
use crate::AdvertisementData;

/// Message kind for `DiscoveryMessage` type
#[derive(Copy, Clone)]
pub enum DiscoveryMessageKind {
    Discovery,
    Announce,
    ExtendAnnouncements,
}

impl DiscoveryMessageKind {
    const fn str_name(&self) -> &'static [u8] {
        match self {
            DiscoveryMessageKind::Discovery => b"discovery",
            DiscoveryMessageKind::Announce => b"announce",
            DiscoveryMessageKind::ExtendAnnouncements => b"extend-announcements",
        }
    }
    const fn pattern(&self) -> [u8; 32] {
        Sha256::new().update(self.str_name()).finalize()
    }

    pub fn try_from_pattern(pattern: &[u8]) -> Option<Self> {
        if pattern == Self::Discovery.pattern() {
            Some(Self::Discovery)
        } else if pattern == Self::Announce.pattern() {
            Some(Self::Announce)
        } else if pattern == Self::ExtendAnnouncements.pattern() {
            Some(Self::ExtendAnnouncements)
        } else {
            None
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
        if msg.len() < 32 {
            debug!("Packet is too small, ignoring...");
            return None;
        }
        let msg_pattern = &msg[..32];
        let Some(msg_type) = DiscoveryMessageKind::try_from_pattern(msg_pattern) else {
            debug!("Unknown discovery message pattern, ignoring...");
            return None;
        };

        let msg_body = &msg[32..];
        match msg_type {
            DiscoveryMessageKind::Announce if msg_body.len() >= 2+4+1 => {
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
            }
            DiscoveryMessageKind::Discovery if msg_body.is_empty() => {
                Some(DiscoveryMessage::Discovery)
            }
            DiscoveryMessageKind::ExtendAnnouncements if msg_body.is_empty() => {
                Some(DiscoveryMessage::ExtendAnnouncements)
            }
            _ => {
                debug!("Discovery message has invalid length, ignoring...");
                None
            }
        }
    }
    pub(crate) fn gen_message(&self) -> Vec<u8> {
        let pattern = self.msg_type().pattern();
        match self {
            DiscoveryMessage::Discovery => pattern.to_vec(),
            DiscoveryMessage::Announce { service_port, discover_id, disconnected, adv_data } => {
                let mut hello_msg = pattern.to_vec();
                hello_msg.extend_from_slice(service_port.to_be_bytes().as_ref());
                hello_msg.extend_from_slice(discover_id.to_be_bytes().as_ref());
                hello_msg.push(*disconnected as u8);
                hello_msg.extend_from_slice(&adv_data.encode_to_bytes());
                hello_msg
            }
            DiscoveryMessage::ExtendAnnouncements => pattern.to_vec(),
        }
    }
}
