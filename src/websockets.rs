use anyhow::{Result, anyhow};
use bincode::{Decode, Encode};
use ed25519_dalek::ed25519::SignatureBytes;
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use rand::rngs::OsRng;
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_websockets::{ClientBuilder, ServerBuilder, WebSocketStream};

use crate::crypto::{PrivateIdentity, PublicIdentity};
use crate::proto::RawMessage;
use crate::router::{RouterInterface, RouterMessage, UntaggedConnection};

#[derive(Encode, Decode, Debug)]
struct HelloMessage {
    id: PublicIdentity,
    nonce: [u8; 8],
}

#[derive(Encode, Decode, Debug)]
struct SignedMessage {
    message: HelloMessage,
    signature: SignatureBytes,
}

impl HelloMessage {
    fn to_vec(&self) -> Result<Vec<u8>> {
        Ok(bincode::encode_to_vec(self, bincode::config::standard())?)
    }

    fn into_signed_message(self, id: &PrivateIdentity) -> Result<SignedMessage> {
        let signature = id.sign(self.to_vec()?);
        Ok(SignedMessage {
            message: self,
            signature,
        })
    }

    fn new(id: PublicIdentity) -> Self {
        let mut csprng = OsRng;
        let mut nonce: [u8; 8] = [0; 8];
        csprng.fill_bytes(&mut nonce);
        Self { id, nonce }
    }
}

impl SignedMessage {
    fn to_vec(&self) -> Result<Vec<u8>> {
        Ok(bincode::encode_to_vec(self, bincode::config::standard())?)
    }

    fn decode(msg: Vec<u8>) -> Result<Self> {
        Ok(bincode::decode_from_slice::<SignedMessage, _>(
            msg.as_slice(),
            bincode::config::standard(),
        )?
        .0)
    }

    fn verify(&self) -> Result<bool> {
        self.message
            .id
            .verify(self.message.to_vec()?, &self.signature)
    }
}

async fn handshake_challenge<S>(
    wss: &mut WebSocketStream<S>,
    id: &PrivateIdentity,
) -> Result<SignedMessage>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let hello = HelloMessage::new(id.public_id.clone()).into_signed_message(id)?;
    wss.send(tokio_websockets::Message::binary(hello.to_vec()?))
        .await?;
    Ok(hello)
}

async fn handshake_response<S>(
    wss: &mut WebSocketStream<S>,
    id: &PrivateIdentity,
) -> Result<PublicIdentity>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let challenge = {
        let Some(msg) = wss.next().await else {
            return Err(anyhow!("websocket closed unexpectedly"));
        };
        SignedMessage::decode(msg?.into_payload().to_vec())?
    };
    if !challenge.verify()? {
        return Err(anyhow!("invalid signature"));
    }
    let res = HelloMessage {
        id: id.public_id.clone(),
        nonce: challenge.message.nonce,
    };
    wss.send(tokio_websockets::Message::binary(
        res.into_signed_message(id)?.to_vec()?,
    ))
    .await?;
    Ok(challenge.message.id)
}

async fn handshake_verify_response<S>(
    wss: &mut WebSocketStream<S>,
    challenge: &SignedMessage,
) -> Result<PublicIdentity>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let response = {
        let Some(msg) = wss.next().await else {
            return Err(anyhow!("websocket closed unexpectedly"));
        };
        SignedMessage::decode(msg?.into_payload().to_vec())?
    };
    if !response.verify()? {
        return Err(anyhow!("invalid signature"));
    }
    if challenge.message.nonce != response.message.nonce {
        log::error!("challenge nonce doesn't match {challenge:?}");
        return Err(anyhow!("nonce doesn't match"));
    }
    Ok(response.message.id)
}

async fn handshake<S>(wss: &mut WebSocketStream<S>, id: &PrivateIdentity) -> Result<PublicIdentity>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    log::debug!("sending challenge");
    let challenge = handshake_challenge(wss, id).await?;
    log::debug!("responding to challenge");
    let pub_id_2 = handshake_response(wss, id).await?;
    log::debug!("verifying");
    let pub_id = handshake_verify_response(wss, &challenge).await?;
    if pub_id == pub_id_2 {
        Ok(pub_id)
    } else {
        Err(anyhow!("pub id doesn't match"))
    }
}

async fn run_websockets_connection<S>(
    mut wss: WebSocketStream<S>,
    id: PrivateIdentity,
    inbound: bool,
) -> Result<((UntaggedConnection, Option<PublicIdentity>), JoinHandle<()>)>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let their_id = handshake(&mut wss, &id).await?;
    let (in_tx, in_rx) = mpsc::channel(64);
    let (out_tx, mut out_rx) = mpsc::channel::<RawMessage>(64);

    let join_handle = tokio::task::spawn_local(async move {
        loop {
            let from_ws = wss.next();
            let from_router = out_rx.recv();
            tokio::select! {
                msg = from_ws => {
                    let Some(Ok(msg)) = msg else { break; };
                    if (msg.is_binary() || msg.is_text())
                            && in_tx.send(RawMessage(msg.into_payload().to_vec())).await.is_err() {
                        break;
                    }
                }
                msg = from_router => {
                    let Some(msg) = msg else { break; };
                    if wss.send(tokio_websockets::Message::binary(msg.0)).await.is_err() {
                        break;
                    }
                }
                else => {
                    break;
                }
            }
        }
        log::info!("websockets disconnected");
    });
    Ok((
        (UntaggedConnection(out_tx, in_rx, inbound), Some(their_id)),
        join_handle,
    ))
}

pub async fn connect_websockets<A>(
    router: &RouterInterface,
    id: PrivateIdentity,
    addr: A,
) -> Result<JoinHandle<()>>
where
    A: ToSocketAddrs,
{
    let stream = TcpStream::connect(addr).await?;
    let ws_stream = ClientBuilder::new()
        .uri("ws://host/")?
        .connect_on(stream)
        .await?
        .0;
    let (connection, join_handle) = run_websockets_connection(ws_stream, id, false).await?;
    if let Err(e) = router.add_connection(connection.0, connection.1).await {
        log::error!("{}", e);
        join_handle.abort();
    }
    log::debug!("handshake successful");
    Ok(join_handle)
}

pub async fn listen_websockets<A>(
    router: RouterInterface,
    id: PrivateIdentity,
    addr: A,
) -> Result<JoinHandle<Result<()>>>
where
    A: ToSocketAddrs,
{
    let listener = TcpListener::bind(addr).await?;
    log::info!("websockets listening");
    let listening = tokio::task::spawn_local(async move {
        while let Ok((stream, _)) = listener.accept().await {
            log::info!("new websockets connection");
            let connection_router = router.clone();
            let conn_id = id.clone();
            tokio::task::spawn_local(async move {
                let Ok((_, ws_stream)) = ServerBuilder::new().accept(stream).await else {
                    log::error!("websockets failed");
                    return;
                };
                match run_websockets_connection(ws_stream, conn_id, true).await {
                    Ok((connection, join_handle)) => {
                        log::info!("websockets handshake successful");
                        if let Err(e) = connection_router
                            .add_connection(connection.0, connection.1)
                            .await
                        {
                            log::error!("{}", e);
                            join_handle.abort();
                        }
                    }
                    Err(err) => {
                        log::error!("handshake not successful");
                        log::error!("{err:?}");
                    }
                }
            });
        }
        Ok(())
    });
    Ok(listening)
}
