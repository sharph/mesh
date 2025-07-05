use std::collections::VecDeque;
use std::sync::mpsc::channel;
use std::time::Duration;

use anyhow::Result;
use bincode::{Decode, Encode};
use config::Config;
use ed25519_dalek::ed25519::SignatureBytes;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::crypto::{self, PrivateIdentity, PublicIdentity};
use crate::websockets::{connect_websockets, listen_websockets};

#[derive(Clone, Debug)]
pub struct RawMessage(pub Vec<u8>);
#[derive(Copy, Clone, Serialize, Deserialize, Debug, Encode, Decode)]
pub struct ConnectionId(pub u64);

#[derive(Clone, Debug)]
pub struct TaggedRawMessage {
    connection_id: ConnectionId,
    msg: RawMessage,
}

#[derive(Debug, Encode, Decode, Clone)]
pub enum MessagePayload {
    Noop,
    Hello1(PublicIdentity, Vec<u8>),
    Hello2(PublicIdentity, PublicIdentity, Vec<u8>),
    Flood,
    Ping,
    Unicast(Vec<u8>),
    Disconnect,
}

#[derive(Debug, Encode, Decode)]
pub struct MeshMessage {
    from: Option<crypto::PublicIdentity>,
    to: Option<crypto::PublicIdentity>,
    ttl: u8,
    route: VecDeque<ConnectionId>,
    payload: MessagePayload,
    signature: Option<SignatureBytes>,
}

impl MeshMessage {
    fn sign(&mut self, id: &PrivateIdentity) -> Result<()> {
        let serialized_payload = bincode::encode_to_vec::<MessagePayload, _>(
            self.payload.clone(),
            bincode::config::standard(),
        )?;
        self.signature = Some(id.sign(serialized_payload));
        Ok(())
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

pub struct UntaggedConnection(
    pub mpsc::Sender<RawMessage>,
    pub mpsc::Receiver<RawMessage>,
    pub bool,
);

pub struct TaggedConnection(
    mpsc::Sender<RawMessage>,
    mpsc::UnboundedReceiver<TaggedRawMessage>,
);

struct Connection {
    connection_id: ConnectionId,
    id: Option<PublicIdentity>,
    tx: Option<mpsc::Sender<RawMessage>>,
    inbound: bool,
}

impl Connection {
    fn send_message(&mut self, message: RawMessage) -> Result<()> {
        if let Some(tx) = &self.tx {
            let tx = tx.clone();
            if !tx.is_closed() {
                tokio::spawn(async move {
                    let _ = tx.send(message).await;
                });
            } else {
                println!("connection closed");
                self.tx = None;
            }
        }
        Ok(())
    }
}

fn tag_connection(
    mut connection: UntaggedConnection,
    connection_id: ConnectionId,
) -> TaggedConnection {
    let sender = connection.0.clone();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            if let Some(msg) = connection.1.recv().await {
                if tx.send(TaggedRawMessage { connection_id, msg }).is_err() {
                    return;
                }
            } else {
                return;
            }
        }
    });
    TaggedConnection(sender, rx)
}
struct RouterState {
    id: PrivateIdentity,
    connections: Vec<Connection>,
}

impl RouterState {
    fn new(id: PrivateIdentity) -> Self {
        Self {
            id,
            connections: Vec::new(),
        }
    }
}

fn add_connection(
    rs: &mut RouterState,
    connection: UntaggedConnection,
    id: Option<PublicIdentity>,
    router_msg_tx: mpsc::Sender<TaggedRawMessage>,
) -> Result<()> {
    let conn_id = ConnectionId(rs.connections.len() as u64);
    let inbound = connection.2;
    let TaggedConnection(tx, mut rx) = tag_connection(connection, conn_id);
    if let Some(some_id) = &id {
        if inbound {
            println!("adding new connection from {}", some_id.base64());
        } else {
            println!("adding new connection to {}", some_id.base64());
        }
    }
    rs.connections.push(Connection {
        connection_id: conn_id,
        id,
        tx: Some(tx),
        inbound,
    });
    tokio::spawn(async move {
        loop {
            if let Some(msg) = rx.recv().await {
                if router_msg_tx.send(msg).await.is_err() {
                    return;
                }
            }
        }
    });
    Ok(())
}

fn send_keepalive(rs: &mut RouterState) {
    let hb = RawMessage::try_from(MeshMessage {
        from: None,
        to: None,
        ttl: 0,
        route: VecDeque::new(),
        payload: MessagePayload::Noop,
        signature: None,
    })
    .unwrap();
    for connection in rs.connections.iter_mut() {
        let _ = connection.send_message(hb.clone());
    }
}

enum RouterControl {}

pub async fn run_router(settings: &Config) -> Result<()> {
    let (connection_tx, mut connection_rx) =
        mpsc::channel::<(UntaggedConnection, Option<PublicIdentity>)>(64);
    let (router_msg_tx, mut router_msg_rx) = mpsc::channel::<TaggedRawMessage>(64);

    let this_id = crypto::PrivateIdentity::new();
    let id = this_id.clone();

    println!("public id: {}", id.public_id);
    println!("private key: {}", id.base64());

    let mut state = RouterState::new(this_id.clone());

    let mut websocket_listener = None;
    if let Ok(addr) = settings.get_string("websockets_listen") {
        println!("listening on {:?}", addr);
        let connection_sender = connection_tx.clone();
        websocket_listener = Some(listen_websockets(connection_sender, id.clone(), addr).await?);
    }

    if let Ok(addr) = settings.get_string("websockets_connect") {
        println!("connecting to {:?}", addr);
        let connection_sender = connection_tx.clone();
        tokio::spawn(connect_websockets(connection_sender, id.clone(), addr));
    }

    let (tx, mut keepalive_rx) = mpsc::channel(1);

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let Ok(_) = tx.send(()).await else { return };
        }
    });

    loop {
        tokio::select! {
            Some((conn, id)) = connection_rx.recv() => {
                add_connection(&mut state, conn, id, router_msg_tx.clone())?;
            }
            Some(val) = router_msg_rx.recv() => {
                println!("{:?}", val);
            }
            _ = keepalive_rx.recv() => {
                send_keepalive(&mut state);
            }
        }
    }
}
