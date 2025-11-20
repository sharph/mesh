use crate::proto::RawMessage;
use anyhow::{Result, anyhow, bail};
use bincode::{Decode, Encode};
use std::collections::VecDeque;

#[derive(Encode, Decode, Debug)]
pub struct Packet(Vec<u8>);

impl Packet {
    pub fn new(val: Vec<u8>) -> Self {
        Self(val)
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

pub struct Packetizer {
    count: u16,
    size: usize,
}

pub struct PacketizedMessage {
    msg: RawMessage,
    msg_id: u16,
    chunk_id: u16,
    chunk_size: usize,
    chunk_count: u16,
}

impl PacketizedMessage {
    fn new(msg: RawMessage, msg_id: u16, chunk_size: usize) -> Self {
        let chunk_count = msg.0.len().div_ceil(chunk_size) as u16;
        Self {
            msg,
            msg_id,
            chunk_id: 0,
            chunk_size,
            chunk_count,
        }
    }
}

impl Iterator for PacketizedMessage {
    type Item = Packet;

    fn next(&mut self) -> Option<Self::Item> {
        if self.chunk_id == self.chunk_count {
            return None;
        }
        let start = self.chunk_size * (self.chunk_id as usize);
        let mut end = self.chunk_size * (self.chunk_id as usize + 1);
        if end > self.msg.0.len() {
            end = self.msg.0.len();
        }
        let mut packet = Vec::<u8>::with_capacity(self.chunk_size + 6);
        packet.extend_from_slice(&self.msg_id.to_be_bytes());
        packet.extend_from_slice(&self.chunk_id.to_be_bytes());
        packet.extend_from_slice(&self.chunk_count.to_be_bytes());
        packet.extend_from_slice(&self.msg.0.as_slice()[start..end]);

        self.chunk_id += 1;
        Some(Packet::new(packet))
    }
}

impl Packetizer {
    pub fn new(size: usize) -> Self {
        Self {
            count: u16::MAX,
            size,
        }
    }

    pub fn packetize(&mut self, msg: RawMessage) -> PacketizedMessage {
        self.count = self.count.wrapping_add(1);
        PacketizedMessage::new(msg, self.count, self.size)
    }
}

pub struct Depacketizer {
    buffer: VecDeque<(u16, u16, Vec<Option<Vec<u8>>>)>,
    size: usize,
}

impl Depacketizer {
    pub fn new(size: usize) -> Self {
        Self {
            buffer: VecDeque::new(),
            size,
        }
    }

    pub fn read_packet(&mut self, packet: Packet) -> Result<Option<RawMessage>> {
        let msg_id = u16::from_be_bytes(packet.0.as_slice()[0..2].try_into()?);
        let chunk_id = u16::from_be_bytes(packet.0.as_slice()[2..4].try_into()?);
        let chunk_count = u16::from_be_bytes(packet.0.as_slice()[4..6].try_into()?);
        let data: Vec<u8> = packet.0.as_slice()[6..].into();
        if chunk_id >= chunk_count {
            bail!("invalid packet")
        }
        let parts = match self
            .buffer
            .iter_mut()
            .find(|(buf_msg_id, buf_chunk_count, _)| {
                *buf_msg_id == msg_id && *buf_chunk_count == chunk_count
            }) {
            Some((_, _, parts)) => parts,
            None => {
                if self.buffer.len() >= self.size {
                    self.buffer.pop_front();
                }
                let parts = vec![None; chunk_count.into()];
                self.buffer.push_back((msg_id, chunk_count, parts));
                self.buffer.back_mut().map(|(_, _, parts)| parts).unwrap()
            }
        };
        let part = parts
            .get_mut(chunk_id as usize)
            .ok_or(anyhow!("chunk_id out of range"))?;
        let _ = part.insert(data);
        let mut raw_message = None;
        if parts.iter().all(|d| d.is_some()) {
            raw_message = Some(RawMessage::new(
                parts.iter_mut().flat_map(|d| d.take().unwrap()).collect(),
            ));
        }
        Ok(raw_message)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::proto::RawMessage;

    #[test]
    fn reconstruction() {
        let mut packetizer = Packetizer::new(3);
        let mut depacketizer = Depacketizer::new(5);
        let msg = RawMessage::new("abc123def".into());
        let mut packet_iter = packetizer.packetize(msg);
        let msg = depacketizer
            .read_packet(packet_iter.next().unwrap())
            .unwrap();
        assert!(msg.is_none());
        let msg = depacketizer
            .read_packet(packet_iter.next().unwrap())
            .unwrap();
        assert!(msg.is_none());
        let msg = depacketizer
            .read_packet(packet_iter.next().unwrap())
            .unwrap();
        assert_eq!(msg.unwrap(), RawMessage::new("abc123def".into()));
    }

    #[test]
    fn out_of_order() {
        let mut packetizer = Packetizer::new(3);
        let mut depacketizer = Depacketizer::new(5);
        let msg = RawMessage::new("abc123def".into());
        let mut packet_iter = packetizer.packetize(msg);
        let m1 = packet_iter.next().unwrap();
        let m2 = packet_iter.next().unwrap();
        let m3 = packet_iter.next().unwrap();
        assert!(packet_iter.next().is_none());
        let msg = depacketizer.read_packet(m2).unwrap();
        assert!(msg.is_none());
        let msg = depacketizer.read_packet(m3).unwrap();
        assert!(msg.is_none());
        let msg = depacketizer.read_packet(m1).unwrap();
        assert_eq!(msg.unwrap(), RawMessage::new("abc123def".into()));
    }

    #[test]
    fn multiple_messages() {
        let mut packetizer = Packetizer::new(3);
        let mut depacketizer = Depacketizer::new(5);
        let msg = RawMessage::new("abc123def".into());
        let mut packet_iter = packetizer.packetize(msg);
        let ma1 = packet_iter.next().unwrap();
        let ma2 = packet_iter.next().unwrap();
        let ma3 = packet_iter.next().unwrap();
        assert!(packet_iter.next().is_none());
        let msg = RawMessage::new("hij456kl".into());
        let mut packet_iter = packetizer.packetize(msg);
        let mb1 = packet_iter.next().unwrap();
        let mb2 = packet_iter.next().unwrap();
        let mb3 = packet_iter.next().unwrap();
        assert!(packet_iter.next().is_none());
        let msg = depacketizer.read_packet(ma2).unwrap();
        assert!(msg.is_none());
        let msg = depacketizer.read_packet(ma3).unwrap();
        assert!(msg.is_none());
        let msg = depacketizer.read_packet(mb1).unwrap();
        assert!(msg.is_none());
        let msg = depacketizer.read_packet(mb2).unwrap();
        assert!(msg.is_none());
        let msg = depacketizer.read_packet(ma1).unwrap();
        assert_eq!(msg.unwrap(), RawMessage::new("abc123def".into()));
        let msg = depacketizer.read_packet(mb3).unwrap();
        assert_eq!(msg.unwrap(), RawMessage::new("hij456kl".into()));
    }

    #[test]
    fn forget_multiple_messages() {
        let mut packetizer = Packetizer::new(3);
        let mut depacketizer = Depacketizer::new(2);
        let msg = RawMessage::new("abc123def".into());
        let mut packet_iter = packetizer.packetize(msg);
        let ma1 = packet_iter.next().unwrap();
        let ma2 = packet_iter.next().unwrap();
        let ma3 = packet_iter.next().unwrap();
        assert!(packet_iter.next().is_none());
        let msg = RawMessage::new("hij456klm".into());
        let mut packet_iter = packetizer.packetize(msg);
        let mb1 = packet_iter.next().unwrap();
        let mb2 = packet_iter.next().unwrap();
        let mb3 = packet_iter.next().unwrap();
        assert!(packet_iter.next().is_none());
        let msg = RawMessage::new("forgetme".into());
        let mut packet_iter = packetizer.packetize(msg);
        let mc1 = packet_iter.next().unwrap();
        let mc2 = packet_iter.next().unwrap();
        let mc3 = packet_iter.next().unwrap();
        assert!(packet_iter.next().is_none());
        let msg = depacketizer.read_packet(mc2).unwrap();
        assert!(msg.is_none());
        let msg = depacketizer.read_packet(ma2).unwrap();
        assert!(msg.is_none());
        let msg = depacketizer.read_packet(ma3).unwrap();
        assert!(msg.is_none());
        let msg = depacketizer.read_packet(mb1).unwrap();
        assert!(msg.is_none());
        let msg = depacketizer.read_packet(mb2).unwrap();
        assert!(msg.is_none());
        let msg = depacketizer.read_packet(ma1).unwrap();
        assert_eq!(msg.unwrap(), RawMessage::new("abc123def".into()));
        let msg = depacketizer.read_packet(mb3).unwrap();
        assert_eq!(msg.unwrap(), RawMessage::new("hij456klm".into()));
        let msg = depacketizer.read_packet(mc1).unwrap();
        assert!(msg.is_none());
        let msg = depacketizer.read_packet(mc3).unwrap();
        assert!(msg.is_none());
    }
}
