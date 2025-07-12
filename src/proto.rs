use std::collections::VecDeque;

use anyhow::Result;
use bincode::{Decode, Encode};
use ed25519_dalek::ed25519::SignatureBytes;
use serde::{Deserialize, Serialize};

use crate::crypto::{PrivateIdentity, PublicIdentity};

pub const DEFAULT_TTL: u8 = 16;

#[derive(Clone, Debug)]
pub struct RawMessage(pub Vec<u8>);
#[derive(Copy, Clone, Serialize, Deserialize, Debug, Encode, Decode, PartialEq, Eq)]
pub struct ConnectionId(pub u64);

#[derive(Clone, Debug)]
pub struct TaggedRawMessage {
    pub connection_id: ConnectionId,
    pub msg: RawMessage,
}

#[derive(Eq, PartialEq, Encode, Decode, Clone, Hash, Debug)]
pub enum MessagePayload {
    Noop,
    Flood(std::time::SystemTime),
    Ping,
    Unicast(Vec<u8>),
    Disconnect,
}

#[derive(Debug, Encode, Decode, Eq, PartialEq, Default, Clone)]
pub struct Route(VecDeque<ConnectionId>);

impl std::ops::Deref for Route {
    type Target = VecDeque<ConnectionId>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Route {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl PartialOrd for Route {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.0.len().cmp(&other.0.len()))
    }
}

impl Ord for Route {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other).unwrap()
    }
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct MeshMessage {
    pub from: Option<PublicIdentity>,
    pub to: Option<PublicIdentity>,
    pub ttl: u8,
    pub route: Route,
    pub payload: MessagePayload,
    pub signature: Option<SignatureBytes>,
}

impl MeshMessage {
    fn flood(id: &PrivateIdentity) -> Result<MeshMessage> {
        let mut msg = MeshMessage {
            from: Some(id.public_id.clone()),
            to: None,
            ttl: DEFAULT_TTL,
            route: Route::default(),
            payload: MessagePayload::Flood(std::time::SystemTime::now()),
            signature: None,
        };
        msg.sign(id)?;
        Ok(msg)
    }

    pub fn sign(&mut self, id: &PrivateIdentity) -> Result<()> {
        let serialized_payload = bincode::encode_to_vec::<MessagePayload, _>(
            self.payload.clone(),
            bincode::config::standard(),
        )?;
        self.signature = Some(id.sign(serialized_payload));
        Ok(())
    }

    pub fn signature_valid(&self) -> Result<bool> {
        let Some(from) = &self.from else {
            return Ok(false);
        };
        let Some(signature) = &self.signature else {
            return Ok(false);
        };
        let serialized_payload = bincode::encode_to_vec::<MessagePayload, _>(
            self.payload.clone(),
            bincode::config::standard(),
        )?;
        Ok(from.verify(serialized_payload, &signature)?)
    }
}

impl TryFrom<RawMessage> for MeshMessage {
    type Error = anyhow::Error;

    fn try_from(msg: RawMessage) -> Result<Self> {
        Ok(bincode::decode_from_slice::<MeshMessage, _>(
            msg.0.as_slice(),
            bincode::config::standard(),
        )?
        .0)
    }
}

impl TryFrom<MeshMessage> for RawMessage {
    type Error = anyhow::Error;

    fn try_from(msg: MeshMessage) -> Result<Self> {
        Ok(Self(bincode::encode_to_vec(
            msg,
            bincode::config::standard(),
        )?))
    }
}
