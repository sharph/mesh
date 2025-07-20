use crate::{
    crypto::{EncryptionSession, KeyExchange, KeyExchangeMessage, PrivateIdentity, PublicIdentity},
    proto::{MeshMessage, MessagePayload, Route, UnicastMessage, UnicastMessagePayload},
};
use anyhow::{Result, anyhow, bail};
use futures_util::future;
use tokio::sync::mpsc::{Receiver, Sender, channel};

pub enum RouteManagementMessage {
    Add(Route),
    Delete(Route),
}

#[derive(Default)]
struct Routes(Option<Route>);

impl Routes {
    // very basic "one route" implementation
    fn handle_message(&mut self, msg: &RouteManagementMessage) {
        match msg {
            RouteManagementMessage::Add(route) => {
                if let Some(old_route) = self.0.as_ref() {
                    if route < old_route {
                        self.0 = Some(route.clone())
                    }
                } else {
                    self.0 = Some(route.clone());
                }
                log::debug!("unicast add route: {:?}", self.0);
            }
            RouteManagementMessage::Delete(route) => {
                if Some(route) == self.0.as_ref() {
                    self.0 = None
                }
                log::debug!("unicast del route: {:?}", self.0);
            }
        }
    }

    fn has_route(&self) -> bool {
        self.0.is_some()
    }

    fn get_route(&self) -> Option<&Route> {
        self.0.as_ref()
    }
}

async fn get_msg_or_block<T>(rx: &mut Receiver<T>, should_block: bool) -> Option<T> {
    if should_block {
        future::pending::<()>().await;
    }
    rx.recv().await
}

pub struct UnicastConnection {
    route_management_tx: Sender<RouteManagementMessage>,
    message_receiving_tx: Sender<MeshMessage>,
    unicast_sending_tx: Sender<UnicastMessage>,
}

impl UnicastConnection {
    pub fn is_closed(&self) -> bool {
        self.route_management_tx.is_closed()
            || self.message_receiving_tx.is_closed()
            || self.unicast_sending_tx.is_closed()
    }

    pub fn send_unicast(&self, msg: UnicastMessage) -> Result<()> {
        Ok(self.unicast_sending_tx.try_send(msg)?)
    }

    pub fn receive_mesh_message(&self, msg: MeshMessage) -> Result<()> {
        Ok(self.message_receiving_tx.try_send(msg)?)
    }

    pub fn add_route(&self, route: Route) -> Result<()> {
        Ok(self
            .route_management_tx
            .try_send(RouteManagementMessage::Add(route))?)
    }

    pub fn delete_route(&self, route: Route) -> Result<()> {
        Ok(self
            .route_management_tx
            .try_send(RouteManagementMessage::Delete(route))?)
    }
}

#[derive(Default)]
struct CryptoState {
    decrypt_session: Option<EncryptionSession>,
    encrypt_session: Option<EncryptionSession>,
    key_exchange: Option<KeyExchange>,
}

impl CryptoState {
    fn ready(&self) -> bool {
        self.encrypt_session.is_some()
    }

    fn decrypt_mesh_message(&self, msg: &MeshMessage) -> Result<UnicastMessage> {
        UnicastMessage::from_mesh_message(
            msg,
            self.decrypt_session
                .as_ref()
                .ok_or(anyhow!("no active crypto session"))?,
        )
    }

    fn encrypt_unicast_message(
        &mut self,
        to: PublicIdentity,
        msg: &UnicastMessage,
        route: Route,
    ) -> Result<MeshMessage> {
        msg.into_mesh_message(
            to,
            route,
            self.encrypt_session
                .as_mut()
                .ok_or(anyhow!("no active crypto session"))?,
        )
    }

    fn get_key_exchange_1(&mut self) -> KeyExchangeMessage {
        self.key_exchange
            .get_or_insert_with(|| KeyExchange::new())
            .public()
    }

    fn handle_key_exhange_1(&mut self, kex_msg: &KeyExchangeMessage) -> Result<KeyExchangeMessage> {
        let kex = KeyExchange::new_from_other_message(kex_msg);
        let public = kex.public();
        self.decrypt_session = Some(kex.into_encryption_session(kex_msg)?);
        Ok(public)
    }

    fn handle_key_exchange_2(&mut self, kex_msg: &KeyExchangeMessage) -> Result<()> {
        let Some(kex) = self.key_exchange.take() else {
            bail!("no active key exchange");
        };
        self.encrypt_session = Some(kex.into_encryption_session(kex_msg)?);
        Ok(())
    }
}

enum UnicastOption {
    UnicastMessage(UnicastMessage),
    MeshMessage(MeshMessage),
    RouteManagement(RouteManagementMessage),
    EndConnection,
}

pub fn run_unicast_connection(
    our_id: PrivateIdentity,
    their_id: PublicIdentity,
    message_sending_tx: Sender<MeshMessage>,
    unicast_receiving_tx: Sender<UnicastMessage>,
) -> UnicastConnection {
    let (route_management_tx, mut route_mgmt_rx) = channel(64);
    let (message_receiving_tx, mut message_receiving_rx) = channel(64);
    let (unicast_sending_tx, mut unicast_sending_rx) = channel(64);
    let mut routes = Routes::default();
    log::info!("new unicast connection");
    let mut crypto_state = CryptoState::default();
    tokio::spawn(async move {
        loop {
            let has_route = routes.has_route();
            let ready = has_route && crypto_state.ready();
            let option = tokio::select! {
                msg = unicast_sending_rx.recv(), if ready => {
                    // process messages only when encrypted path is setup
                    if let Some(msg) = msg {
                        UnicastOption::UnicastMessage(msg)
                    } else {
                        UnicastOption::EndConnection
                    }
                }
                msg = message_receiving_rx.recv(), if has_route => {
                    // don't start processing kex messages until we have a route
                    if let Some(msg) = msg {
                        UnicastOption::MeshMessage(msg)
                    } else {
                        UnicastOption::EndConnection
                    }
                },
                msg = route_mgmt_rx.recv() => {
                    if let Some(msg) = msg {
                        UnicastOption::RouteManagement(msg)
                    } else {
                        UnicastOption::EndConnection
                    }
                }
            };
            match option {
                UnicastOption::MeshMessage(msg) => {
                    let MessagePayload::Unicast(unicast_msg_payload) = &msg.payload else {
                        continue;
                    };
                    match unicast_msg_payload {
                        UnicastMessagePayload::EncryptedPayload(_) => {
                            if let Ok(uni_msg) = crypto_state.decrypt_mesh_message(&msg) {
                                // convert a message from the mesh into a local message
                                let _ = unicast_receiving_tx.send(uni_msg).await;
                            }
                            // TODO: fix broken sessions
                        }
                        UnicastMessagePayload::KeyExchange1(kex) => {
                            if !msg.signature_valid().unwrap_or(false) {
                                continue;
                            }
                            if let Some(route) = routes.get_route()
                                && let Ok(reply) = crypto_state.handle_key_exhange_1(kex)
                            {
                                let Ok(msg) = MeshMessage::unicast_sign(
                                    &our_id,
                                    their_id.clone(),
                                    route.clone(),
                                    UnicastMessagePayload::KeyExchange2(reply),
                                ) else {
                                    continue;
                                };
                                let _ = message_sending_tx.send(msg).await;
                            };
                        }
                        UnicastMessagePayload::KeyExchange2(kex) => {
                            if !msg.signature_valid().unwrap_or(false) {
                                continue;
                            }
                            let _ = crypto_state.handle_key_exchange_2(kex);
                        }
                    }
                }
                UnicastOption::UnicastMessage(msg) => {
                    if let Some(route) = routes.get_route()
                        && let Ok(msg) = crypto_state.encrypt_unicast_message(
                            their_id.clone(),
                            &msg,
                            route.clone(),
                        )
                    {
                        let _ = message_sending_tx.send(msg).await;
                    }
                }
                UnicastOption::RouteManagement(msg) => {
                    routes.handle_message(&msg);
                    if let Some(route) = routes.get_route()
                        && crypto_state.key_exchange.is_none()
                        && let Ok(msg) = MeshMessage::unicast_sign(
                            &our_id,
                            their_id.clone(),
                            route.clone(),
                            UnicastMessagePayload::KeyExchange1(crypto_state.get_key_exchange_1()),
                        )
                    {
                        let _ = message_sending_tx.send(msg).await;
                    }
                }
                UnicastOption::EndConnection => break,
            };
        }
    });
    UnicastConnection {
        route_management_tx,
        message_receiving_tx,
        unicast_sending_tx,
    }
}
