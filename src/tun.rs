use crate::proto::{self, UnicastMessage};
use crate::tun;
use anyhow::{Result, bail};
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc::{Sender, channel};
use tun_rs::async_framed::{BytesCodec, DeviceFramed};
use tun_rs::{AsyncDevice, DeviceBuilder};

use pnet::packet::{self, Packet, ipv6};
use std::net::Ipv6Addr;

use crate::crypto::{PublicIdentity, ShortId};

impl PublicIdentity {
    pub fn to_ipv6_address(&self) -> Ipv6Addr {
        Ipv6Addr::new(
            0xfc00,
            0x35,
            (self.short_id()[0] as u16) << 8 | (self.short_id()[1] as u16),
            (self.short_id()[2] as u16) << 8 | (self.short_id()[3] as u16),
            (self.short_id()[4] as u16) << 8 | (self.short_id()[5] as u16),
            (self.short_id()[6] as u16) << 8 | (self.short_id()[7] as u16),
            (self.short_id()[8] as u16) << 8 | (self.short_id()[9] as u16),
            (self.short_id()[10] as u16) << 8 | (self.short_id()[11] as u16),
        )
    }
}

fn ipv6_to_unicast_destination(addr: Ipv6Addr) -> Result<proto::UnicastDestination> {
    let short_id: ShortId = addr.octets()[4..32].try_into()?;
    Ok(proto::UnicastDestination::ShortId(short_id))
}

struct TunPayload {
    from_addr: Ipv6Addr,
    to_addr: Ipv6Addr,
    header: [u8; 8],
    payload: Vec<u8>,
}

impl TunPayload {
    fn from_ipv6_packet(packet: &Vec<u8>) -> Result<Self> {
        let from_bytes: [u8; 16] = packet.as_slice()[8..24].try_into()?;
        let from_addr = Ipv6Addr::from(from_bytes);
        let to_bytes: [u8; 16] = packet.as_slice()[24..40].try_into()?;
        let to_addr = Ipv6Addr::from(to_bytes);
        let header = packet.as_slice()[0..8].try_into()?;
        let payload = packet.as_slice()[40..].to_vec();
        Ok(Self {
            from_addr,
            to_addr,
            header,
            payload,
        })
    }

    fn to_ipv6_packet(&self) -> Vec<u8> {
        [
            self.header.to_vec(),
            self.from_addr.octets().to_vec(),
            self.to_addr.octets().to_vec(),
            self.payload.clone(),
        ]
        .concat()
    }

    fn to_mesh_message(&self) -> Vec<u8> {
        [self.header.to_vec(), self.payload.clone()].concat()
    }

    fn new(from: &PublicIdentity, to: &PublicIdentity, payload: &Vec<u8>) -> Result<Self> {
        Ok(Self {
            from_addr: from.to_ipv6_address(),
            to_addr: to.to_ipv6_address(),
            header: payload.as_slice()[0..8].try_into()?,
            payload: payload.as_slice()[8..].into(),
        })
    }
}

fn handle_packet(
    our_id: &PublicIdentity,
    packet: &Vec<u8>,
    tx: &mut Sender<proto::UnicastMessage>,
) -> Result<()> {
    let tun_payload = TunPayload::from_ipv6_packet(packet)?;
    if tun_payload.from_addr.segments()[0..2] != [0xfc00, 0x35]
        || tun_payload.to_addr.segments()[0..2] != [0xfc00, 0x35]
    {
        bail!("invalid packet from tun");
    }
    if tun_payload.from_addr != our_id.to_ipv6_address() {
        bail!("packet not from our mesh id");
    }
    tx.try_send(UnicastMessage {
        to: proto::UnicastDestination::ShortId(tun_payload.to_addr.octets()[4..16].try_into()?),
        from: our_id.clone(),
        payload: proto::UnicastMessagePayload::Payload(1, tun_payload.to_mesh_message()),
    })
    .unwrap();
    Ok(())
}

async fn handle_from_mesh(
    msg: &proto::UnicastMessage,
    our_ip: &Ipv6Addr,
    device: &mut DeviceFramed<BytesCodec>,
) -> Result<()> {
    let proto::UnicastDestination::PublicIdentity(to) = &msg.to else {
        bail!("we don't know how to handle a message with a short id")
    };
    let proto::UnicastMessagePayload::Payload(_, payload) = &msg.payload else {
        bail!("got a payload that wasn't unicast");
    };
    let tun_payload = TunPayload::new(&msg.from, &to, &payload)?;
    let bytes = BytesMut::try_from(tun_payload.to_ipv6_packet().as_slice())?;
    device.send(bytes).await?;
    Ok(())
}

pub fn run_tun(
    id: &PublicIdentity,
    mut unicast_out: Sender<proto::UnicastMessage>,
) -> Result<Sender<proto::UnicastMessage>> {
    let (unicast_in_tx, mut unicast_in) = channel(64);
    let dev = DeviceBuilder::new()
        .ipv6(id.to_ipv6_address(), 32)
        .mtu(2048)
        .build_async()?;

    let mut framed = DeviceFramed::new(dev, BytesCodec::new());

    let id = id.clone();
    tokio::spawn(async move {
        let our_ip = id.to_ipv6_address();
        loop {
            tokio::select! {
                Some(packet) = framed.next() => {
                    if let Ok(packet) = packet {
                        let _ = handle_packet(&id, &packet.to_vec(), &mut unicast_out);
                    } else {
                        println!("couldn't get packet");
                    }
                }
                msg = unicast_in.recv() => {
                    if let Some(msg) = msg {
                        let _ = handle_from_mesh(&msg, &our_ip, &mut framed).await;
                    }
                }
            }
        }
    });
    Ok(unicast_in_tx)
}
