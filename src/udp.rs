use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use crate::crypto::{PrivateIdentity, PublicIdentity};
use crate::packetizer::{Depacketizer, Packet, Packetizer};
use crate::proto::RawMessage;
use crate::router::{RouterInterface, UntaggedConnection};
use anyhow::{Error, Result, anyhow, bail};
use bincode::{Decode, Encode};
use rand::RngCore;
use rand::rngs::OsRng;
use tokio::net::{ToSocketAddrs, UdpSocket};
use tokio::sync::mpsc::{Sender, channel};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

const MAX_PAYLOAD_SIZE: usize = 800;
const HEARTBEAT_PERIOD: std::time::Duration = Duration::from_secs(1);
const CONNECTION_TIMEOUT: std::time::Duration = Duration::from_secs(5);

#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
struct UdpSessionIdentity(u16, PublicIdentity);

impl UdpSessionIdentity {}

#[derive(Encode, Decode, Debug)]
enum UdpPacket {
    /// Initiate a connection
    Establish(UdpSessionIdentity),
    /// Let the other side know the connection is established. Can be sent at any time.
    Established(UdpSessionIdentity),
    /// Tell the other side a session of a given number is disconnected
    Disconnected(u16),
    SessionMessage(u16, Packet),
}

impl TryFrom<Vec<u8>> for UdpPacket {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> std::result::Result<Self, Self::Error> {
        Ok(bincode::decode_from_slice::<Self, _>(&value, bincode::config::standard())?.0)
    }
}

impl TryInto<Vec<u8>> for UdpPacket {
    type Error = Error;

    fn try_into(self) -> std::result::Result<Vec<u8>, Self::Error> {
        Ok(bincode::encode_to_vec(self, bincode::config::standard())?)
    }
}

#[derive(Default, Eq, PartialEq, Clone)]
enum UdpSessionState {
    #[default]
    Unconnected,
    Establishing(u16),
    Established(UdpSessionIdentity),
    Disconnected,
}

struct UdpSession {
    state: UdpSessionState,
    addr: SocketAddr,
    to_net: Sender<(SocketAddr, Vec<u8>)>,
    to_router: Sender<RawMessage>,
    packetizer: Packetizer,
    depacketizer: Depacketizer,
    our_id: PrivateIdentity,
    timeouts: u16,
}

impl UdpSession {
    fn new(
        addr: SocketAddr,
        to_net: Sender<(SocketAddr, Vec<u8>)>,
        to_router: Sender<RawMessage>,
        our_id: PrivateIdentity,
    ) -> Self {
        Self {
            state: UdpSessionState::default(),
            addr,
            to_net,
            to_router,
            packetizer: Packetizer::new(MAX_PAYLOAD_SIZE),
            depacketizer: Depacketizer::new(16),
            our_id,
            timeouts: 0,
        }
    }

    fn try_send_net(&self, packet: UdpPacket) -> Result<()> {
        self.to_net.try_send((self.addr, packet.try_into()?))?;
        Ok(())
    }

    fn is_ready(&self) -> bool {
        matches!(self.state, UdpSessionState::Established(_))
    }

    async fn send_net(&self, packet: UdpPacket) -> Result<()> {
        self.to_net.send((self.addr, packet.try_into()?)).await?;
        Ok(())
    }

    async fn handle_from_mesh(&mut self, msg: RawMessage) -> Result<()> {
        let UdpSessionState::Established(sid) = &self.state else {
            bail!("session not established");
        };
        for packet in self.packetizer.packetize(msg) {
            self.send_net(UdpPacket::SessionMessage(sid.0, packet))
                .await?;
        }
        Ok(())
    }

    async fn send_initiation(&mut self) -> Result<()> {
        let mut rng = OsRng;
        let sess_id = <u16>::from_be_bytes(rng.next_u32().to_be_bytes()[0..2].try_into()?);
        self.send_net(UdpPacket::Establish(UdpSessionIdentity(
            sess_id,
            self.our_id.public_id.clone(),
        )))
        .await?;
        self.state = UdpSessionState::Establishing(sess_id);
        Ok(())
    }

    fn send_heartbeat(&mut self) -> Result<()> {
        if let UdpSessionState::Established(sid) = &self.state {
            self.try_send_net(UdpPacket::Established(UdpSessionIdentity(
                sid.0,
                self.our_id.public_id.clone(),
            )))?;
        } else {
            bail!("connection not established");
        }
        Ok(())
    }

    fn disconnect(&mut self) -> Result<()> {
        if let UdpSessionState::Established(sid) = &self.state {
            self.try_send_net(UdpPacket::Disconnected(sid.0))?;
            self.state = UdpSessionState::Disconnected;
        } else {
            bail!("connection not established");
        }
        Ok(())
    }

    async fn handle_from_net(&mut self, packet: Vec<u8>) -> Result<()> {
        let packet: UdpPacket = packet.try_into()?;
        match (self.state.clone(), packet) {
            (UdpSessionState::Unconnected, UdpPacket::Establish(sid)) => {
                if self
                    .try_send_net(UdpPacket::Established(UdpSessionIdentity(
                        sid.0,
                        self.our_id.public_id.clone(),
                    )))
                    .is_ok()
                {
                    self.state = UdpSessionState::Established(sid);
                    log::info!("UDP connection established with {:?}", self.addr);
                }
            }
            (UdpSessionState::Unconnected, UdpPacket::SessionMessage(sid, _)) => {
                let _ = self.try_send_net(UdpPacket::Disconnected(sid));
                self.state = UdpSessionState::Disconnected;
            }
            (UdpSessionState::Unconnected, UdpPacket::Established(sid)) => {
                let _ = self.try_send_net(UdpPacket::Disconnected(sid.0));
                self.state = UdpSessionState::Disconnected;
            }
            (UdpSessionState::Unconnected, UdpPacket::Disconnected(_)) => {
                self.state = UdpSessionState::Disconnected;
            }
            (UdpSessionState::Establishing(sid), UdpPacket::Establish(packet_sid)) => {
                if sid != packet_sid.0 {
                    let _ = self.try_send_net(UdpPacket::Established(UdpSessionIdentity(
                        sid,
                        self.our_id.public_id.clone(),
                    )));
                    self.state = UdpSessionState::Established(packet_sid);
                    log::info!("UDP connection established with {:?}", self.addr);
                } else {
                    let _ = self.try_send_net(UdpPacket::Disconnected(packet_sid.0));
                    self.state = UdpSessionState::Disconnected;
                }
            }
            (UdpSessionState::Establishing(sid), UdpPacket::Established(packet_sid)) => {
                if sid == packet_sid.0 {
                    self.state = UdpSessionState::Established(packet_sid.clone());
                    log::info!("UDP connection established with {:?}", self.addr);
                    let _ = self.try_send_net(UdpPacket::Established(UdpSessionIdentity(
                        sid,
                        self.our_id.public_id.clone(),
                    )));
                }
            }
            (UdpSessionState::Establishing(sid), UdpPacket::SessionMessage(packet_sid, _)) => {
                if sid == packet_sid {
                    let _ = self.try_send_net(UdpPacket::Established(UdpSessionIdentity(
                        sid,
                        self.our_id.public_id.clone(),
                    )));
                }
            }
            (UdpSessionState::Establishing(sid), UdpPacket::Disconnected(packet_sid)) => {
                if sid == packet_sid {
                    self.state = UdpSessionState::Disconnected;
                }
            }
            (UdpSessionState::Established(sid), UdpPacket::Establish(packet_sid)) => {
                if sid == packet_sid {
                    let _ = self.try_send_net(UdpPacket::Established(UdpSessionIdentity(
                        sid.0,
                        self.our_id.public_id.clone(),
                    )));
                } else {
                    let _ = self.try_send_net(UdpPacket::Disconnected(packet_sid.0));
                }
            }
            (UdpSessionState::Established(sid), UdpPacket::Established(packet_sid)) => {
                if sid != packet_sid {
                    let _ = self.try_send_net(UdpPacket::Disconnected(packet_sid.0));
                }
            }
            (UdpSessionState::Established(sid), UdpPacket::SessionMessage(packet_sid, packet)) => {
                if sid.0 != packet_sid {
                    // remind the other side which session we think is active.
                    // this will prompt a disconnect from the other side if it
                    // doesn't match
                    let _ = self.try_send_net(UdpPacket::Established(UdpSessionIdentity(
                        sid.0,
                        self.our_id.public_id.clone(),
                    )));
                } else if let Ok(Some(msg)) = self.depacketizer.read_packet(packet) {
                    self.to_router.send(msg).await?;
                }
            }
            (UdpSessionState::Established(sid), UdpPacket::Disconnected(packet_sid)) => {
                if sid.0 == packet_sid {
                    self.state = UdpSessionState::Disconnected;
                }
            }
            (UdpSessionState::Disconnected, _) => {}
        }
        Ok(())
    }
}

async fn udp_session(
    addr: SocketAddr,
    to_net: Sender<(SocketAddr, Vec<u8>)>,
    router: RouterInterface,
    our_id: PrivateIdentity,
    inbound: bool,
) -> (JoinHandle<Result<()>>, Sender<Vec<u8>>) {
    let (tx, mut from_net) = channel::<Vec<u8>>(64);
    let (tx_from_router, mut from_router) = channel::<RawMessage>(64);
    let (tx_to_router, to_router) = channel::<RawMessage>(1);
    let mut to_router = Some(to_router);
    let mut session = UdpSession::new(addr, to_net, tx_to_router, our_id);
    let join_handle = tokio::task::spawn_local(async move {
        if !inbound {
            session.send_initiation().await?;
        }
        let mut heartbeat_deadline = tokio::time::Instant::now()
            .checked_add(HEARTBEAT_PERIOD)
            .expect("reasonable time values");
        let mut connection_timeout_deadline = tokio::time::Instant::now()
            .checked_add(CONNECTION_TIMEOUT)
            .expect("reasonable time values");
        loop {
            tokio::select! {
                msg = from_net.recv() => {
                    let Some(msg) = msg else { break; };
                    let _ = session.handle_from_net(msg).await;
                    connection_timeout_deadline = tokio::time::Instant::now()
                        .checked_add(CONNECTION_TIMEOUT)
                        .expect("reasonable time values");
                },
                msg = from_router.recv(), if session.is_ready() => {
                    let Some(msg) = msg else { break; };
                    let _ = session.handle_from_mesh(msg).await;
                    heartbeat_deadline = tokio::time::Instant::now()
                        .checked_add(HEARTBEAT_PERIOD)
                        .expect("reasonable time values");
                },
                _ = tokio::time::sleep_until(heartbeat_deadline), if session.is_ready() => {
                    heartbeat_deadline = tokio::time::Instant::now()
                        .checked_add(HEARTBEAT_PERIOD)
                        .expect("reasonable time values");
                    let _ = session.send_heartbeat();
                },
                _ = tokio::time::sleep_until(connection_timeout_deadline) => {
                    let _ = session.disconnect();
                    bail!("connection with {} timed out", addr);
                },
            }
            if matches!(session.state, UdpSessionState::Established(_))
                && let Some(to_router) = to_router.take()
            {
                if let Err(e) = router
                    .add_connection(
                        UntaggedConnection(tx_from_router.clone(), to_router, inbound),
                        None,
                    )
                    .await
                {
                    log::error!(
                        "couldn't add UDP connection with {:?} to router: {:?}",
                        addr,
                        e
                    );
                    return Err(e);
                }
                heartbeat_deadline = tokio::time::Instant::now()
                    .checked_add(HEARTBEAT_PERIOD)
                    .expect("reasonable time values");
                connection_timeout_deadline = tokio::time::Instant::now()
                    .checked_add(CONNECTION_TIMEOUT)
                    .expect("reasonable time values");
            } else if matches!(session.state, UdpSessionState::Disconnected) {
                log::info!("UDP connection with {:?} disconnected", addr);
                break;
            }
        }
        Ok(()) as Result<()>
    });
    (join_handle, tx)
}

#[derive(Clone)]
pub struct UDPServiceInterface(
    Sender<(SocketAddr, oneshot::Sender<Result<JoinHandle<Result<()>>>>)>,
);

impl UDPServiceInterface {
    pub async fn connect(&self, addr: SocketAddr) -> Result<JoinHandle<Result<()>>> {
        let (tx, rx) = oneshot::channel::<Result<JoinHandle<Result<()>>>>();
        self.0.send((addr, tx)).await?;
        rx.await?
    }

    pub fn is_closed(&self) -> bool {
        self.0.is_closed()
    }
}

pub async fn run_udp<A>(
    addr: A,
    router: RouterInterface,
    our_id: PrivateIdentity,
) -> Result<UDPServiceInterface>
where
    A: ToSocketAddrs,
{
    let (tx, mut rx) = channel::<(SocketAddr, Vec<u8>)>(64);
    let (connect_tx, mut connect_rx) =
        channel::<(SocketAddr, oneshot::Sender<Result<JoinHandle<Result<()>>>>)>(1);
    let mut sessions: HashMap<SocketAddr, Sender<Vec<u8>>> = HashMap::new();
    let sock = UdpSocket::bind(addr).await?;
    let mut buf = [0; 1024];
    tokio::task::spawn_local(async move {
        if let Ok(sock_addr) = sock.local_addr() {
            log::info!("UDP listening on {:?}", sock_addr);
        }
        loop {
            tokio::select! {
                res = sock.recv_from(&mut buf) => {
                    let Ok((len, addr)) = res else { break; };
                    if let Some(tx) = sessions.get(&addr) && !tx.is_closed() {
                        let _ = tx.try_send(buf[0..len].into());
                    } else {
                        log::info!("accepting UDP from {:?}", addr);
                        let (_, tx) = udp_session(addr, tx.clone(), router.clone(), our_id.clone(), true).await;
                        let _ = tx.try_send(buf[0..len].into());
                        sessions.insert(addr, tx);
                    }
                },
                received = rx.recv() => {
                    let Some((socket, data)) = received else { break; };
                    if let Err(e) = sock.send_to(data.as_slice(), socket).await {
                        log::error!("{}", e);
                    }
                },
                Some((connect_to, connect_return_tx)) = connect_rx.recv() => {
                    if let Some(session) = sessions.get(&connect_to) && !session.is_closed() {
                        let _ = connect_return_tx.send(Err(anyhow!("UDP connection already exists")));
                        continue;
                    }
                    log::info!("connecting to {:?} with UDP", connect_to);
                    let (join_handle, tx) = udp_session(connect_to, tx.clone(), router.clone(), our_id.clone(), false).await;
                    sessions.insert(connect_to, tx);
                    let _ = connect_return_tx.send(Ok(join_handle));
                }
            }
        }
        log::debug!("UDP ended");
    });
    Ok(UDPServiceInterface(connect_tx))
}
