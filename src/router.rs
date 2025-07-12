use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use tokio::sync::mpsc;

use crate::crypto::{self, PrivateIdentity, PublicIdentity};
use crate::proto::{
    ConnectionId, DEFAULT_TTL, MeshMessage, MessagePayload, RawMessage, Route, TaggedRawMessage,
};
use crate::websockets::{connect_websockets, listen_websockets};

const FLOOD_DB_SIZE: usize = 1024 * 8;

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
        if let Some(old_instant) = self.db.insert(entry.clone(), instant) {
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
            db_entry.seen.contains_key(route)
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
            let best_in_route_db = self.route_db.observe_route(from_id, &msg.route);
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
        if let MessagePayload::Flood(_) = msg.payload {
            self.handle_flood(&msg, conn)?
        }
        Ok(())
    }
}

pub struct RouterConfig {
    pub websockets_listen: Vec<String>,
    pub websockets_connect: Vec<String>,
}

pub async fn run_router(config: &RouterConfig) -> Result<()> {
    let (connection_tx, mut connection_rx) =
        mpsc::channel::<(UntaggedConnection, Option<PublicIdentity>)>(64);
    let (router_msg_tx, mut router_msg_rx) = mpsc::channel::<TaggedRawMessage>(64);

    let this_id = crypto::PrivateIdentity::new();
    let id = this_id.clone();

    println!("public id: {}", id.public_id);
    println!("private key: {}", id.base64());

    let mut state = RouterState::new(this_id.clone());

    let _listen_handles = config
        .websockets_listen
        .iter()
        .map(|addr| {
            println!("ws listening on {addr:?}");
            let connection_sender = connection_tx.clone();
            tokio::spawn(listen_websockets(
                connection_sender,
                id.clone(),
                addr.clone(),
            ))
        })
        .collect::<Vec<_>>();
    let _connect_handles = config
        .websockets_connect
        .iter()
        .map(|addr| {
            println!("ws connecting to {addr:?}");
            let connection_sender = connection_tx.clone();
            tokio::spawn(connect_websockets(
                connection_sender,
                id.clone(),
                addr.clone(),
            ))
        })
        .collect::<Vec<_>>();

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
