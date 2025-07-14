use crate::{
    crypto::PublicIdentity,
    proto::{MeshMessage, Route, UnicastMessage},
};
use anyhow::Result;
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
            }
            RouteManagementMessage::Delete(route) => {
                if Some(route) == self.0.as_ref() {
                    self.0 = None
                }
            }
        }
        println!("route: {:?}", self.0);
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

async fn send_to_mesh(
    their_id: &PublicIdentity,
    route: Route,
    msg: UnicastMessage,
    tx: &mut Sender<MeshMessage>,
) -> Result<()> {
    let msg = msg.into_mesh_message(their_id.clone(), route);
    tx.send(msg).await?;
    Ok(())
}

async fn send_to_local(msg: MeshMessage, tx: &mut Sender<UnicastMessage>) -> Result<()> {
    let msg = UnicastMessage::from_mesh_message(msg)?;
    tx.send(msg).await?;
    Ok(())
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
        println!("fn add_route");
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

pub fn run_unicast_connection(
    our_id: PublicIdentity,
    their_id: PublicIdentity,
    mut message_sending_tx: Sender<MeshMessage>,
    mut unicast_receiving_tx: Sender<UnicastMessage>,
) -> UnicastConnection {
    let (route_management_tx, mut route_mgmt_rx) = channel(64);
    let (message_receiving_tx, mut message_receiving_rx) = channel(64);
    let (unicast_sending_tx, mut unicast_sending_rx) = channel(64);
    let mut routes = Routes::default();
    println!("new unicast connection");
    tokio::spawn(async move {
        loop {
            tokio::select! {
                msg = get_msg_or_block(&mut unicast_sending_rx, !routes.has_route()) => {
                    if let (Some(msg), Some(route)) = (msg, routes.get_route()) {
                        if send_to_mesh(&their_id, route.clone(), msg, &mut message_sending_tx).await.is_err() {
                            break;
                        }
                    } else {
                        break;
                    }
                },
                msg = message_receiving_rx.recv() => {
                    if let Some(msg) = msg {
                        if send_to_local(msg, &mut unicast_receiving_tx).await.is_err() {
                            break;
                        }
                    } else {
                        break;
                    }
                },
                msg = route_mgmt_rx.recv() => {
                    if let Some(msg) = msg {
                        routes.handle_message(&msg);
                    } else {
                        break;
                    }
                }
            }
        }
    });
    UnicastConnection {
        route_management_tx,
        message_receiving_tx,
        unicast_sending_tx,
    }
}
