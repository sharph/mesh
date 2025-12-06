use std::collections::VecDeque;

use anyhow::{Result, anyhow, bail};
use bincode::{Decode, Encode};
use ed25519_dalek::ed25519::SignatureBytes;
use serde::{Deserialize, Serialize};

use crate::crypto::{
    EncryptedMessage, EncryptionSession, KeyExchangeMessage, PrivateIdentity, PublicIdentity,
    SessionId, ShortId,
};

pub const DEFAULT_TTL: u8 = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawMessage(pub Vec<u8>);

impl RawMessage {
    pub fn new(msg: Vec<u8>) -> Self {
        Self(msg)
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

#[derive(
    Copy, Clone, Serialize, Deserialize, Debug, Encode, Decode, PartialEq, Eq, Hash, Ord, PartialOrd,
)]
pub struct ConnectionId(pub u64);

#[derive(Clone, Debug)]
pub struct TaggedRawMessage {
    pub connection_id: ConnectionId,
    pub msg: RawMessage,
}

#[derive(Eq, PartialEq, Encode, Decode, Clone, Hash, Debug)]
pub enum UnicastMessagePayload {
    KeyExchange1(KeyExchangeMessage),
    KeyExchange2(KeyExchangeMessage),
    EncryptedPayload(EncryptedMessage),
    CantDecrypt(SessionId),
    Ping(u16, std::time::SystemTime),
    Pong(u16, std::time::SystemTime),
}

#[derive(Eq, PartialEq, Encode, Decode, Clone, Hash, Debug)]
pub struct UnicastPayload(pub u16, pub Vec<u8>);

#[derive(Debug)]
pub enum UnicastDestination {
    ShortId(ShortId),
    PublicIdentity(PublicIdentity),
}

#[derive(Debug)]
pub struct UnicastMessage {
    pub to: UnicastDestination,
    pub from: PublicIdentity,
    pub payload: UnicastPayload,
}

impl UnicastMessage {
    pub fn new(to: UnicastDestination, from: PublicIdentity, payload: UnicastPayload) -> Self {
        Self { to, from, payload }
    }

    pub fn into_mesh_message(
        &self,
        to: PublicIdentity,
        route: Route,
        session: &mut EncryptionSession,
    ) -> Result<MeshMessage> {
        let payload = bincode::encode_to_vec(self.payload.clone(), bincode::config::standard())?;
        Ok(MeshMessage {
            from: Some(self.from.clone()),
            to: Some(to),
            ttl: DEFAULT_TTL,
            trace: Route::default(),
            route,
            payload: MessagePayload::Unicast(UnicastMessagePayload::EncryptedPayload(
                session.encrypt(&payload)?,
            )),
            signature: None,
        })
    }

    pub fn from_mesh_message(
        msg: &MeshMessage,
        session: &EncryptionSession,
    ) -> Result<UnicastMessage> {
        let MessagePayload::Unicast(UnicastMessagePayload::EncryptedPayload(payload)) =
            &msg.payload
        else {
            bail!("MeshMessage didn't have unicast payload")
        };
        let payload = bincode::decode_from_slice::<UnicastPayload, _>(
            session.decrypt(payload)?.as_slice(),
            bincode::config::standard(),
        )?
        .0;
        Ok(UnicastMessage {
            from: msg
                .from
                .as_ref()
                .ok_or_else(|| anyhow!("no 'from' in MeshMessage"))?
                .clone(),
            to: UnicastDestination::PublicIdentity(
                msg.to
                    .as_ref()
                    .ok_or_else(|| anyhow!("no 'to' in MeshMessage"))?
                    .clone(),
            ),
            payload,
        })
    }
}

#[derive(Eq, PartialEq, Encode, Decode, Clone, Hash, Debug)]
pub enum MessagePayload {
    Noop,
    Flood(std::time::SystemTime),
    Ping,
    Unicast(UnicastMessagePayload),
    Disconnect,
}

#[derive(Debug, Encode, Decode, Eq, PartialEq, Default, Clone, Hash, PartialOrd, Ord)]
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

#[derive(Clone, Debug, Encode, Decode)]
pub struct MeshMessage {
    pub from: Option<PublicIdentity>,
    pub to: Option<PublicIdentity>,
    pub ttl: u8,
    pub trace: Route,
    pub route: Route,
    pub payload: MessagePayload,
    pub signature: Option<SignatureBytes>,
}

impl MeshMessage {
    pub fn unicast(
        from: PublicIdentity,
        to: PublicIdentity,
        route: Route,
        payload: UnicastMessagePayload,
    ) -> Self {
        Self {
            from: Some(from),
            to: Some(to),
            trace: Route::default(),
            ttl: DEFAULT_TTL,
            route,
            payload: MessagePayload::Unicast(payload),
            signature: None,
        }
    }

    pub fn unicast_sign(
        from: &PrivateIdentity,
        to: PublicIdentity,
        route: Route,
        payload: UnicastMessagePayload,
    ) -> Result<Self> {
        let mut msg = Self::unicast(from.public_id.clone(), to, route, payload);
        msg.sign(from)?;
        Ok(msg)
    }

    fn flood(id: &PrivateIdentity) -> Result<MeshMessage> {
        let mut msg = MeshMessage {
            from: Some(id.public_id.clone()),
            to: None,
            ttl: DEFAULT_TTL,
            trace: Route::default(),
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
        Ok(from.verify(serialized_payload, signature)?)
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
