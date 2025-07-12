use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::mpsc::channel;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use bincode::{Decode, Encode};
use config::Config;
use ed25519_dalek::ed25519::SignatureBytes;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::crypto::{self, PrivateIdentity, PublicIdentity};
use crate::websockets::{connect_websockets, listen_websockets};

const DEFAULT_TTL: u8 = 16;
const FLOOD_DB_SIZE: usize = 1024 * 8;

#[derive(Clone, Debug)]
pub struct RawMessage(pub Vec<u8>);
#[derive(Copy, Clone, Serialize, Deserialize, Debug, Encode, Decode, PartialEq, Eq)]
pub struct ConnectionId(pub u64);

#[derive(Clone, Debug)]
pub struct TaggedRawMessage {
    connection_id: ConnectionId,
    msg: RawMessage,
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
struct Route(VecDeque<ConnectionId>);

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
    from: Option<crypto::PublicIdentity>,
    to: Option<crypto::PublicIdentity>,
    ttl: u8,
    route: Route,
    payload: MessagePayload,
    signature: Option<SignatureBytes>,
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

    fn sign(&mut self, id: &PrivateIdentity) -> Result<()> {
        let serialized_payload = bincode::encode_to_vec::<MessagePayload, _>(
            self.payload.clone(),
            bincode::config::standard(),
        )?;
        self.signature = Some(id.sign(serialized_payload));
        Ok(())
    }

    fn signature_valid(&self) -> Result<bool> {
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
                if tx.try_send(message).is_err() {
                    println!("buffer full");
                }
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

#[derive(Eq, PartialEq, Hash, Clone)]
struct FloodDBEntry {
    id: PublicIdentity,
    payload: MessagePayload,
}

impl FloodDBEntry {
    fn new(id: PublicIdentity, payload: MessagePayload) -> Self {
        Self { id, payload }
    }
}

#[derive(Default)]
struct FloodDB {
    db: HashMap<FloodDBEntry, std::time::Instant>,
    instants: BTreeMap<std::time::Instant, FloodDBEntry>,
}

impl FloodDB {
    fn has(&self, entry: &FloodDBEntry) -> bool {
        self.db.contains_key(entry)
    }

    fn trim(&mut self) {
        while self.db.len() > FLOOD_DB_SIZE {
            let (_, oldest) = self.instants.pop_first().unwrap();
            self.db.remove(&oldest).unwrap();
        }
    }

    fn update(&mut self, entry: FloodDBEntry) -> bool {
        let instant = Instant::now();
        let mut updated = false;
        if let Some(old_instant) = self.db.insert(entry.clone(), instant.clone()) {
            self.instants.remove(&old_instant).unwrap();
            updated = true
        }
        self.instants.insert(instant, entry);
        self.trim();
        updated
    }
}
#[derive(Default)]
struct RouteDBEntry {
    seen: BTreeMap<Route, Instant>,
    instants: BTreeMap<Instant, Route>,
}

#[derive(Default)]
struct RouteDB(BTreeMap<PublicIdentity, RouteDBEntry>);

impl RouteDB {
    fn is_route_in_db(&self, id: &PublicIdentity, route: &Route) -> bool {
        if let Some(db_entry) = self.0.get(id) {
            db_entry.seen.get(route).is_some()
        } else {
            false
        }
    }

    fn trim_routes(&mut self) {}

    /// Adds route to db and returns true if route is shortest
    fn observe_route(&mut self, id: &PublicIdentity, route: &Route) -> bool {
        let instant = Instant::now();
        if let Some(rec) = self.0.get_mut(id) {
            if let Some(old_instant) = rec.seen.remove(route) {
                rec.instants.remove(&old_instant).unwrap();
            }
            rec.seen.insert(route.clone(), instant);
            rec.instants.insert(instant, route.clone());
            rec.seen.first_key_value().unwrap().0 == route
        } else {
            let mut rdb = RouteDBEntry::default();
            rdb.seen.insert(route.clone(), instant);
            rdb.instants.insert(instant, route.clone());
            self.0.insert(id.clone(), rdb);
            true
        }
    }
}

struct RouterState {
    id: PrivateIdentity,
    connections: Vec<Connection>,
    route_db: RouteDB,
    flood_db: FloodDB,
}

impl RouterState {
    fn new(id: PrivateIdentity) -> Self {
        Self {
            id,
            connections: Vec::new(),
            route_db: RouteDB::default(),
            flood_db: FloodDB::default(),
        }
    }

    fn add_connection(
        &mut self,
        connection: UntaggedConnection,
        id: Option<PublicIdentity>,
        router_msg_tx: mpsc::Sender<TaggedRawMessage>,
    ) -> Result<()> {
        let conn_id = ConnectionId(self.connections.len() as u64);
        let inbound = connection.2;
        let TaggedConnection(tx, mut rx) = tag_connection(connection, conn_id);
        if let Some(some_id) = &id {
            if inbound {
                println!("adding new connection from {}", some_id.base64());
            } else {
                println!("adding new connection to {}", some_id.base64());
            }
        }
        self.connections.push(Connection {
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

    fn send_to_all(&mut self, msg: MeshMessage, except: Option<ConnectionId>) -> Result<()> {
        let raw_message = RawMessage::try_from(msg)?;
        for connection in self.connections.iter_mut() {
            if Some(connection.connection_id) == except {
                continue;
            }
            let _ = connection.send_message(raw_message.clone());
        }
        Ok(())
    }

    fn handle_flood(&mut self, msg: &MeshMessage, from: ConnectionId) -> Result<()> {
        let mut msg = msg.clone();
        if !msg.signature_valid()? {
            bail!("signature invalid");
        }
        // TODO: check flood time
        // TODO: enforce a local ttl
        if let Some(from_id) = &msg.from {
            println!("got flood from {}", from_id.base64());
            let in_flood_db = self
                .flood_db
                .update(FloodDBEntry::new(from_id.clone(), msg.payload.clone()));
            let best_in_route_db = self.route_db.observe_route(&from_id, &msg.route);
            if (in_flood_db && best_in_route_db) || (msg.ttl as usize) < msg.route.len() {
                return Ok(());
            }
            msg.route.push_front(from);
            self.send_to_all(msg.clone(), Some(from))?;
        }
        Ok(())
    }

    async fn send_keepalive(&mut self) {
        let hb = RawMessage::try_from(MeshMessage {
            from: None,
            to: None,
            ttl: 0,
            route: Route::default(),
            payload: MessagePayload::Noop,
            signature: None,
        })
        .unwrap();
        for connection in self.connections.iter_mut() {
            let _ = connection.send_message(hb.clone());
        }
    }

    fn send_flood(&mut self) -> Result<()> {
        let mut msg = MeshMessage {
            from: Some(self.id.public_id.clone()),
            to: None,
            ttl: DEFAULT_TTL,
            route: Route::default(),
            payload: MessagePayload::Flood(std::time::SystemTime::now()),
            signature: None,
        };
        println!("sending flood from {}", msg.from.clone().unwrap().base64());
        msg.sign(&self.id)?;
        self.send_to_all(msg, None)?;
        Ok(())
    }

    fn handle_message(&mut self, msg: TaggedRawMessage) -> Result<()> {
        let conn = msg.connection_id;
        let msg = MeshMessage::try_from(msg.msg)?;
        match msg.payload {
            MessagePayload::Flood(_) => self.handle_flood(&msg, conn)?,
            _ => {}
        }
        Ok(())
    }
}

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

    let (tx, mut flood_rx) = mpsc::channel(1);

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let Ok(_) = tx.send(()).await else { return };
        }
    });

    loop {
        tokio::select! {
            Some((conn, id)) = connection_rx.recv() => {
                state.add_connection(conn, id, router_msg_tx.clone())?;
            }
            Some(val) = router_msg_rx.recv() => {
                let _ = state.handle_message(val);
            }
            _ = flood_rx.recv() => {
                let _ = state.send_flood();
            }
        }
    }
}
