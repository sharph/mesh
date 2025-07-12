use anyhow::{Result, anyhow};
use bincode::{Decode, Encode};
use ed25519_dalek::ed25519::SignatureBytes;
use futures_util::{Sink, SinkExt, StreamExt};
use rand::RngCore;
use rand::rngs::OsRng;
use tokio::net::{TcpListener, TcpSocket, TcpStream, ToSocketAddrs};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_websockets::{ClientBuilder, ServerBuilder, WebSocketStream};

use crate::crypto::{PrivateIdentity, PublicIdentity};
use crate::node::UntaggedConnection;
use crate::proto::RawMessage;

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

    fn to_signed_message(self, id: &PrivateIdentity) -> Result<SignedMessage> {
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
    let hello = HelloMessage::new(id.public_id.clone()).to_signed_message(&id)?;
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
        res.to_signed_message(&id)?.to_vec()?,
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
        println!("{:?}", challenge);
        println!("{:?}", response);
        return Err(anyhow!("nonce doesn't match"));
    }
    Ok(response.message.id)
}

async fn handshake<S>(wss: &mut WebSocketStream<S>, id: &PrivateIdentity) -> Result<PublicIdentity>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    println!("sending challenge");
    let challenge = handshake_challenge(wss, id).await?;
    println!("responding to challenge");
    let pub_id_2 = handshake_response(wss, id).await?;
    println!("verifying");
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
) -> Result<(UntaggedConnection, Option<PublicIdentity>)>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let their_id = handshake(&mut wss, &id).await?;
    let (in_tx, in_rx) = mpsc::channel(64);
    let (out_tx, mut out_rx) = mpsc::channel::<RawMessage>(64);

    tokio::spawn(async move {
        loop {
            let from_ws = wss.next();
            let from_router = out_rx.recv();
            tokio::select! {
                Some(Ok(msg)) = from_ws => {
                    if (msg.is_binary() || msg.is_text())
                            && in_tx.send(RawMessage(msg.into_payload().to_vec())).await.is_err() {
                        break;
                    }
                }
                Some(msg) = from_router => {
                    if wss.send(tokio_websockets::Message::binary(msg.0)).await.is_err() {
                        break;
                    }
                }
                else => {
                    break;
                }
            }
        }
        println!("disconnected");
    });
    Ok((UntaggedConnection(out_tx, in_rx, inbound), Some(their_id)))
}

pub async fn connect_websockets<A>(
    connection_sender: mpsc::Sender<(UntaggedConnection, Option<PublicIdentity>)>,
    id: PrivateIdentity,
    addr: A,
) -> Result<()>
where
    A: ToSocketAddrs,
{
    let stream = TcpStream::connect(addr).await?;
    let ws_stream = ClientBuilder::new()
        .uri("ws://host/")?
        .connect_on(stream)
        .await?
        .0;
    let connection = run_websockets_connection(ws_stream, id, false).await?;
    let _ = connection_sender.send(connection).await;
    println!("handshake successful");
    Ok(())
}

pub async fn listen_websockets<A>(
    connection_sender: mpsc::Sender<(UntaggedConnection, Option<PublicIdentity>)>,
    id: PrivateIdentity,
    addr: A,
) -> Result<JoinHandle<Result<()>>>
where
    A: ToSocketAddrs,
{
    let listener = TcpListener::bind(addr).await?;
    println!("listening");
    let listening = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            println!("new connection");
            let tx = connection_sender.clone();
            let conn_id = id.clone();
            tokio::spawn(async move {
                let Ok((_, ws_stream)) = ServerBuilder::new().accept(stream).await else {
                    println!("websockets failed");
                    return;
                };
                match run_websockets_connection(ws_stream, conn_id, true).await {
                    Ok(connection) => {
                        println!("handshake successful");
                        let _ = tx.send(connection).await;
                    }
                    Err(err) => {
                        println!("handshake not successful");
                        println!("{:?}", err);
                    }
                }
            });
        }
        Ok(())
    });
    Ok(listening)
}
