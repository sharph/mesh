use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use tokio::sync::mpsc;

use crate::crypto::{self, PrivateIdentity, PublicIdentity, ShortId};
use crate::proto::{
    ConnectionId, DEFAULT_TTL, MeshMessage, MessagePayload, RawMessage, Route, TaggedRawMessage,
    UnicastDestination, UnicastMessage,
};
use crate::tun;
use crate::unicast::{UnicastConnection, run_unicast_connection};
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
    unicast_connection: Option<UnicastConnection>,
}

#[derive(Default)]
struct RouteDB {
    routes: BTreeMap<PublicIdentity, RouteDBEntry>,
    short_id_lookup: HashMap<ShortId, PublicIdentity>,
}

impl RouteDB {
    fn is_route_in_db(&self, id: &PublicIdentity, route: &Route) -> bool {
        if let Some(db_entry) = self.routes.get(id) {
            db_entry.seen.contains_key(route)
        } else {
            false
        }
    }

    fn get_route(&mut self, id: &PublicIdentity) -> Option<&mut RouteDBEntry> {
        self.routes.get_mut(id)
    }

    fn get_route_for_unicast_destination(
        &mut self,
        dest: &UnicastDestination,
    ) -> Option<(PublicIdentity, &mut RouteDBEntry)> {
        match dest {
            UnicastDestination::ShortId(short_id) => {
                if let Some(id) = self.short_id_lookup.get(short_id) {
                    let id = id.clone();
                    self.get_route(&id).map(|r| (id, r))
                } else {
                    None
                }
            }
            UnicastDestination::PublicIdentity(pub_id) => {
                self.get_route(pub_id).map(|r| (pub_id.clone(), r))
            }
        }
    }

    fn trim_routes(&mut self) {}

    /// Adds route to db and returns true if route is shortest
    fn observe_route(&mut self, id: &PublicIdentity, route: &Route) -> bool {
        let instant = Instant::now();
        self.short_id_lookup.insert(id.short_id(), id.clone());
        if let Some(rec) = self.routes.get_mut(id) {
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
            self.routes.insert(id.clone(), rdb);
            true
        }
    }
}

struct RouterState {
    id: PrivateIdentity,
    connections: Vec<Connection>,
    route_db: RouteDB,
    flood_db: FloodDB,
    message_sending_tx: mpsc::Sender<MeshMessage>,
    unicast_sending_tx: mpsc::Sender<UnicastMessage>,
    unicast_receiving_tx: mpsc::Sender<UnicastMessage>,
}

impl RouterState {
    fn new(
        id: PrivateIdentity,
        message_sending_tx: mpsc::Sender<MeshMessage>,
        unicast_sending_tx: mpsc::Sender<UnicastMessage>,
        unicast_receiving_tx: mpsc::Sender<UnicastMessage>,
    ) -> Self {
        Self {
            id,
            connections: Vec::new(),
            route_db: RouteDB::default(),
            flood_db: FloodDB::default(),
            message_sending_tx,
            unicast_sending_tx,
            unicast_receiving_tx,
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

    fn send_to(&mut self, msg: MeshMessage, to: ConnectionId) -> Result<()> {
        println!("{msg:?} {to:?}");
        let raw_message = RawMessage::try_from(msg)?;
        let Some(connection) = self.connections.get_mut(to.0 as usize) else {
            bail!("invalid connection")
        };
        connection.send_message(raw_message.clone())?;
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
            msg.trace.push_front(from);
            let in_flood_db = self
                .flood_db
                .update(FloodDBEntry::new(from_id.clone(), msg.payload.clone()));
            let best_in_route_db = self.route_db.observe_route(from_id, &msg.trace);
            if (in_flood_db && best_in_route_db) || (msg.ttl as usize) < msg.trace.len() {
                return Ok(());
            }
            self.send_to_all(msg.clone(), Some(from))?;
        }
        Ok(())
    }

    async fn send_keepalive(&mut self) {
        let hb = RawMessage::try_from(MeshMessage {
            from: None,
            to: None,
            ttl: 0,
            trace: Route::default(),
            route: Route::default(),
            payload: MessagePayload::Noop,
            signature: None,
        })
        .unwrap();
        for connection in self.connections.iter_mut() {
            let _ = connection.send_message(hb.clone());
        }
    }

    fn send_message(&mut self, mut msg: MeshMessage) -> Result<()> {
        match msg.payload {
            MessagePayload::Unicast(_) => {
                let dest = msg.route.pop_front().ok_or(anyhow!("no route!"))?;
                self.send_to(msg, dest)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn send_flood(&mut self) -> Result<()> {
        let mut msg = MeshMessage {
            from: Some(self.id.public_id.clone()),
            to: None,
            ttl: DEFAULT_TTL,
            trace: Route::default(),
            route: Route::default(),
            payload: MessagePayload::Flood(std::time::SystemTime::now()),
            signature: None,
        };
        msg.sign(&self.id)?;
        self.send_to_all(msg, None)?;
        Ok(())
    }

    fn handle_message(&mut self, msg: TaggedRawMessage) -> Result<()> {
        let conn = msg.connection_id;
        let mut msg = MeshMessage::try_from(msg.msg)?;
        match msg.payload {
            MessagePayload::Flood(_) => self.handle_flood(&msg, conn)?,
            MessagePayload::Unicast(_) => {
                if msg.to.as_ref() == Some(&self.id.public_id) || msg.route.is_empty() {
                    self.handle_unicast_for_us(msg)?
                } else if let Some(next_hop) = msg.route.pop_front() {
                    msg.trace.push_front(conn);
                    self.send_to(msg, next_hop)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn get_unicast_connection(
        &mut self,
        dest: &UnicastDestination,
    ) -> Result<&mut UnicastConnection> {
        let Some((id, route_db_entry)) = self.route_db.get_route_for_unicast_destination(dest)
        else {
            bail!("no route")
        };
        if route_db_entry.unicast_connection.is_none() {
            route_db_entry.unicast_connection = Some(run_unicast_connection(
                self.id.clone(),
                id,
                self.message_sending_tx.clone(),
                self.unicast_receiving_tx.clone(),
            ));
            route_db_entry
                .unicast_connection
                .as_mut()
                .unwrap()
                .add_route(route_db_entry.seen.first_key_value().unwrap().0.clone())?;
        }
        Ok(route_db_entry.unicast_connection.as_mut().unwrap())
    }

    fn handle_unicast_for_us(&mut self, msg: MeshMessage) -> Result<()> {
        self.get_unicast_connection(&UnicastDestination::PublicIdentity(
            msg.from.as_ref().ok_or(anyhow!("no from field"))?.clone(),
        ))?
        .receive_mesh_message(msg)?;
        Ok(())
    }

    fn send_unicast_message(&mut self, msg: UnicastMessage) -> Result<()> {
        self.get_unicast_connection(&msg.to)?.send_unicast(msg)?;
        // TODO: detect closed connections
        Ok(())
    }
}

pub struct RouterConfig {
    pub websockets_listen: Vec<String>,
    pub websockets_connect: Vec<String>,
    pub tun: bool,
}

pub async fn run_router(config: &RouterConfig) -> Result<()> {
    let (connection_tx, mut connection_rx) =
        mpsc::channel::<(UntaggedConnection, Option<PublicIdentity>)>(64);
    let (router_msg_tx, mut router_msg_rx) = mpsc::channel::<TaggedRawMessage>(64);
    let (msg_sending_tx, mut msg_sending_rx) = mpsc::channel::<MeshMessage>(64);
    let (unicast_sending_tx, mut unicast_sending_rx) = mpsc::channel::<UnicastMessage>(64);
    let (unicast_receiving_tx, mut unicast_receiving_rx) = mpsc::channel::<UnicastMessage>(64);

    let this_id = crypto::PrivateIdentity::new();
    let id = this_id.clone();

    println!("public id: {}", id.public_id);
    println!("private key: {}", id.base64());

    let mut state = RouterState::new(
        this_id.clone(),
        msg_sending_tx,
        unicast_sending_tx.clone(),
        unicast_receiving_tx,
    );

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

    println!("{}", id.public_id.to_ipv6_address());
    let mut tun_tx = if config.tun {
        let id_for_tun = id.public_id.clone();
        Some(tun::run_tun(&id_for_tun, unicast_sending_tx.clone())?)
    } else {
        None
    };

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
                // a message comes in from a remote connection
                let _ = state.handle_message(val);
            }
            Some(msg) = msg_sending_rx.recv() => {
                // some local service wants to send a MeshMessage
                let _ = state.send_message(msg);
            }
            Some(msg) = unicast_sending_rx.recv() => {
                // some local service wants to send a message.
                // this codepath turns it into a MeshMessage and sends it
                // out remotely
                let _ = state.send_unicast_message(msg);
            }
            Some(msg) = unicast_receiving_rx.recv() => {
                if let Some(ttx) = tun_tx.as_mut() {
                    let _ = ttx.try_send(msg);
                } else {
                    println!("{msg:?}");
                }
            }
            _ = flood_rx.recv() => {
                let _ = state.send_flood();
            }
        }
    }
}
