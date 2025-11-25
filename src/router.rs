use std::collections::{BTreeMap, HashMap, VecDeque};
use std::ops::{Deref, DerefMut};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use tokio::sync::mpsc;

use crate::crypto::{self, PrivateIdentity, PublicIdentity, ShortId};
use crate::proto::{
    ConnectionId, DEFAULT_TTL, MeshMessage, MessagePayload, RawMessage, Route, TaggedRawMessage,
    UnicastDestination, UnicastMessage,
};
use crate::tun;
use crate::udp::run_udp;
use crate::unicast::{UnicastConnection, run_unicast_connection};
use crate::websockets::{connect_websockets, listen_websockets};

const FLOOD_DB_SIZE: usize = 1024 * 8;
const FLOOD_ANNOUNCE_SEC: u64 = 10;

pub struct UntaggedConnection(
    pub mpsc::Sender<RawMessage>,
    pub mpsc::Receiver<RawMessage>,
    pub bool,
);

pub struct TaggedConnection(mpsc::Sender<RawMessage>, mpsc::Receiver<TaggedRawMessage>);

#[derive(Debug)]
struct Connection {
    connection_id: ConnectionId,
    id: Option<PublicIdentity>,
    tx: Option<mpsc::Sender<RawMessage>>,
    inbound: bool,
}

impl Connection {
    fn send_message(&mut self, message: RawMessage) -> Result<()> {
        if let Some(tx) = &self.tx {
            if !tx.is_closed() {
                if tx.try_send(message).is_err() {
                    log::error!("connection buffer full");
                }
            } else {
                log::info!("connection closed");
                self.tx = None;
            }
        }
        Ok(())
    }

    fn is_closed(&mut self) -> bool {
        if let Some(tx) = &self.tx
            && tx.is_closed()
        {
            log::info!("connection closed");
            self.tx = None;
        }
        self.tx.is_none()
    }
}

fn tag_connection(
    mut connection: UntaggedConnection,
    connection_id: ConnectionId,
) -> TaggedConnection {
    let sender = connection.0.clone();
    let (tx, rx) = mpsc::channel(1);
    tokio::task::spawn_local(async move {
        loop {
            if let Some(msg) = connection.1.recv().await {
                if tx
                    .send(TaggedRawMessage { connection_id, msg })
                    .await
                    .is_err()
                {
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

#[derive(Eq, PartialEq, Clone, Hash)]
struct SortableByLength<T>(T);

impl<T> SortableByLength<T> {
    fn into_inner(self) -> T {
        self.0
    }
}

impl<T> From<T> for SortableByLength<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> Deref for SortableByLength<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for SortableByLength<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T, X> PartialOrd for SortableByLength<T>
where
    T: PartialOrd,
    T: Eq,
    T: Ord,
    T: PartialEq,
    T: Deref<Target = VecDeque<X>>,
    X: Ord,
{
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T, X> Ord for SortableByLength<T>
where
    T: PartialOrd,
    T: Eq,
    T: Ord,
    T: PartialEq,
    T: Deref<Target = VecDeque<X>>,
    X: Ord,
{
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.0.len().cmp(&other.0.len()) {
            std::cmp::Ordering::Less => std::cmp::Ordering::Less,
            std::cmp::Ordering::Greater => std::cmp::Ordering::Greater,
            std::cmp::Ordering::Equal => self.0.iter().cmp(other.0.iter()),
        }
    }
}

#[derive(Default)]
struct RouteDBEntry {
    seen: BTreeMap<SortableByLength<Route>, Instant>, // btree so that length stays sorted
    unicast_connection: Option<UnicastConnection>,
}

impl RouteDBEntry {
    async fn observe(&mut self, route: &Route) {
        let now = Instant::now();
        let mut close = false;
        if self.seen.insert(route.clone().into(), now).is_none()
            && let Some(connection) = &self.unicast_connection
            && connection.add_route(route.clone()).await.is_err()
        {
            close = true;
        }
        if close {
            self.unicast_connection = None;
        }
    }

    async fn trim(&mut self, del_before: &Instant) {
        let mut close = false;
        if let Some(connection) = &self.unicast_connection {
            for (route, _instant) in self
                .seen
                .iter()
                .filter(|(_route, instant)| *instant < del_before)
            {
                if connection
                    .delete_route(route.clone().into_inner())
                    .await
                    .is_err()
                {
                    close = true;
                    break;
                }
            }
        }
        if close {
            self.unicast_connection = None;
        }
        self.seen.retain(|_route, instant| *instant >= *del_before);
    }

    fn shortest_route(&self) -> Option<&Route> {
        self.seen.first_key_value().map(|(k, _v)| k.deref())
    }

    fn is_empty(&self) -> bool {
        self.seen.len() == 0
    }
}

#[derive(Default)]
struct RouteDB {
    routes: BTreeMap<PublicIdentity, RouteDBEntry>,
    short_id_lookup: HashMap<ShortId, PublicIdentity>,
}

impl RouteDB {
    fn is_route_in_db(&self, id: &PublicIdentity, route: &Route) -> bool {
        if let Some(db_entry) = self.routes.get(id) {
            db_entry.seen.contains_key(&route.clone().into())
        } else {
            false
        }
    }

    fn get_route(&mut self, id: &PublicIdentity) -> Option<&mut RouteDBEntry> {
        self.routes.get_mut(id)
    }

    fn get_or_create_route(&mut self, id: &PublicIdentity) -> &mut RouteDBEntry {
        if !self.routes.contains_key(id) {
            self.routes.insert(id.clone(), RouteDBEntry::default());
        }
        self.routes.get_mut(id).unwrap()
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

    async fn trim_routes(&mut self) {
        let Some(del_before) =
            Instant::now().checked_sub(Duration::from_secs(FLOOD_ANNOUNCE_SEC * 3))
        else {
            return;
        };
        for (_id, route_entry) in self.routes.iter_mut() {
            route_entry.trim(&del_before).await;
        }
    }

    /// Adds route to db and returns true if route is shortest
    async fn observe_route(&mut self, id: &PublicIdentity, route: &Route) -> bool {
        let instant = Instant::now();
        self.short_id_lookup.insert(id.short_id(), id.clone());
        let rec = self.get_or_create_route(id);
        rec.observe(route).await;
        log::debug!(
            "this route {:?}, shortest {:?}",
            route.len(),
            rec.shortest_route().map(|r| r.len())
        );
        if let Some(shortest) = rec.shortest_route()
            && shortest.len() == route.len()
        {
            true
        } else {
            false
        }
    }
}

struct RouterState {
    id: PrivateIdentity,
    connections: Vec<Connection>,
    route_db: RouteDB,
    flood_db: FloodDB,
    tx: mpsc::Sender<RouterMessage>,
}

impl RouterState {
    fn new(id: PrivateIdentity, tx: mpsc::Sender<RouterMessage>) -> Self {
        Self {
            id,
            connections: Vec::new(),
            route_db: RouteDB::default(),
            flood_db: FloodDB::default(),
            tx,
        }
    }

    fn add_connection(
        &mut self,
        connection: UntaggedConnection,
        id: Option<PublicIdentity>,
        router_tx: mpsc::Sender<RouterMessage>,
    ) -> Result<()> {
        let mut append = false;
        let conn_id = ConnectionId(
            self.connections
                .iter_mut()
                .enumerate()
                .map(|(i, c)| (i.try_into(), c.is_closed()))
                .find_map(|(i, c)| if c { Some(i) } else { None })
                .unwrap_or_else(|| {
                    append = true;
                    self.connections.len().try_into()
                })?,
        );

        let inbound = connection.2;
        let TaggedConnection(tx, mut rx) = tag_connection(connection, conn_id);
        if let Some(some_id) = &id {
            if inbound {
                log::info!("adding new connection from {}", some_id.base64());
            } else {
                log::info!("adding new connection to {}", some_id.base64());
            }
        }
        let tagged = Connection {
            connection_id: conn_id,
            id,
            tx: Some(tx),
            inbound,
        };
        if append {
            log::trace!("appending connection {:?}", tagged);
            self.connections.push(tagged);
        } else {
            log::trace!("replacing connection {:?} with {:?}", conn_id, tagged);
            *self
                .connections
                .get_mut(conn_id.0 as usize)
                .expect("conn_id index should exist") = tagged;
        }
        tokio::task::spawn_local(async move {
            loop {
                if let Some(msg) = rx.recv().await {
                    if router_tx
                        .try_send(RouterMessage::IncomingMessage(msg))
                        .is_err()
                        && router_tx.is_closed()
                    {
                        return;
                    }
                } else {
                    break;
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
        log::debug!("{msg:?} {to:?}");
        let raw_message = RawMessage::try_from(msg)?;
        let Some(connection) = self.connections.get_mut(to.0 as usize) else {
            bail!("invalid connection")
        };
        connection.send_message(raw_message.clone())?;
        Ok(())
    }

    async fn handle_flood(&mut self, msg: &MeshMessage, from: ConnectionId) -> Result<()> {
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
            let best_in_route_db = self.route_db.observe_route(from_id, &msg.trace).await;
            if (in_flood_db && !best_in_route_db) || (msg.ttl as usize) < msg.trace.len() {
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

    async fn handle_message(&mut self, msg: TaggedRawMessage) -> Result<()> {
        let conn = msg.connection_id;
        let mut msg = MeshMessage::try_from(msg.msg)?;
        match msg.payload {
            MessagePayload::Flood(_) => self.handle_flood(&msg, conn).await?,
            MessagePayload::Unicast(_) => {
                msg.trace.push_front(conn);
                if msg.to.as_ref() == Some(&self.id.public_id) || msg.route.is_empty() {
                    self.handle_unicast_for_us(msg).await?
                } else if let Some(next_hop) = msg.route.pop_front() {
                    self.send_to(msg, next_hop)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn get_unicast_connection(
        &mut self,
        dest: &UnicastDestination,
    ) -> Result<&mut UnicastConnection> {
        let Some((id, route_db_entry)) = self.route_db.get_route_for_unicast_destination(dest)
        else {
            log::debug!("no route to connect to {:?}", dest);
            bail!("no route")
        };
        if route_db_entry.unicast_connection.is_none() {
            route_db_entry.unicast_connection =
                Some(run_unicast_connection(self.id.clone(), id, self.tx.clone()));
            route_db_entry
                .unicast_connection
                .as_mut()
                .unwrap()
                .add_route(
                    route_db_entry
                        .seen
                        .first_key_value()
                        .unwrap()
                        .0
                        .clone()
                        .into_inner(),
                )
                .await?;
        }
        Ok(route_db_entry.unicast_connection.as_mut().unwrap())
    }

    async fn handle_unicast_for_us(&mut self, msg: MeshMessage) -> Result<()> {
        self.get_unicast_connection(&UnicastDestination::PublicIdentity(
            msg.from.as_ref().ok_or(anyhow!("no from field"))?.clone(),
        ))
        .await?
        .receive_mesh_message(msg)?;
        Ok(())
    }

    async fn send_unicast_message(&mut self, msg: UnicastMessage) -> Result<()> {
        self.get_unicast_connection(&msg.to)
            .await?
            .send_unicast(msg)?;
        // TODO: detect closed connections
        Ok(())
    }
}

pub struct RouterConfig {
    pub websockets_listen: Vec<String>,
    pub websockets_connect: Vec<String>,
    pub udp_listen: Option<String>,
    pub udp_connect: Vec<String>,
    pub tun: bool,
}

pub enum RouterMessage {
    AddConnection(UntaggedConnection, Option<PublicIdentity>),
    IncomingMessage(TaggedRawMessage),
    SendMessage(MeshMessage),
    SendUnicast(UnicastMessage),
    ReceiveUnicast(UnicastMessage),
    SendFlood,
}

pub async fn run_router(config: &RouterConfig) -> Result<()> {
    let (router_tx, mut rx) = mpsc::channel::<RouterMessage>(64);

    let this_id = crypto::PrivateIdentity::new();
    let id = this_id.clone();

    log::info!("public id: {}", id.public_id);
    log::info!("private key: {}", id.base64());

    let mut state = RouterState::new(this_id.clone(), router_tx.clone());

    let _listen_handles = config
        .websockets_listen
        .iter()
        .map(|addr| {
            log::info!("ws listening on {addr:?}");
            tokio::task::spawn_local(listen_websockets(
                router_tx.clone(),
                id.clone(),
                addr.clone(),
            ))
        })
        .collect::<Vec<_>>();
    let _connect_handles = config
        .websockets_connect
        .iter()
        .map(|addr| {
            log::info!("ws connecting to {addr:?}");
            tokio::task::spawn_local(connect_websockets(
                router_tx.clone(),
                id.clone(),
                addr.clone(),
            ))
        })
        .collect::<Vec<_>>();
    if let Some(udp_listen) = &config.udp_listen {
        run_udp(
            udp_listen,
            router_tx.clone(),
            id.clone(),
            config.udp_connect.iter().collect(),
        )
        .await?;
    }

    log::info!("your ipv6: {}", id.public_id.to_ipv6_address());
    let mut tun_tx = if config.tun {
        let id_for_tun = id.public_id.clone();
        Some(tun::run_tun(&id_for_tun, router_tx.clone())?)
    } else {
        None
    };

    let tx = router_tx.clone();

    tokio::task::spawn_local(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let Ok(_) = tx.send(RouterMessage::SendFlood).await else {
                return;
            };
        }
    });

    loop {
        if let Some(router_msg) = rx.recv().await {
            match router_msg {
                RouterMessage::AddConnection(conn, id) => {
                    state.add_connection(conn, id, router_tx.clone())?
                }
                RouterMessage::IncomingMessage(msg) => {
                    let _ = state.handle_message(msg).await;
                }
                RouterMessage::SendMessage(msg) => {
                    let _ = state.send_message(msg);
                }
                RouterMessage::SendUnicast(msg) => {
                    let _ = state.send_unicast_message(msg).await;
                }
                RouterMessage::ReceiveUnicast(msg) => {
                    if let Some(ttx) = tun_tx.as_mut() {
                        let _ = ttx.try_send(msg);
                    } else {
                        log::debug!("unhandled unicast: {msg:?}");
                    }
                }
                RouterMessage::SendFlood => {
                    let _ = state.send_flood();
                    state.route_db.trim_routes().await;
                }
            }
        }
    }
}
