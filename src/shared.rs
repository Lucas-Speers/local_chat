use std::io::{Read, Write};

use rsa::pkcs8::LineEnding;

use crate::BoxedResult;


pub const PORT: u16 = 1823;

pub const LINEENDING: LineEnding = LineEnding::LF;

#[derive(Debug, Clone, Copy)]
pub enum PacketType {
    /// send public key - server
    PubKey = 2,
    /// sends private key - client
    Login = 3,
    /// send message
    SendMessage = 4,
    /// disconnect - client
    Disconnect = 5,
}

impl PacketType {
    pub fn from(byte: u8) -> PacketType {
        use PacketType::*;
        match byte {
            // 1 => RequestKey,
            2 => PubKey,
            3 => Login,
            4 => SendMessage,
            5 => Disconnect,
            _ => Disconnect,
        }
    }
}

#[derive(Debug)]
pub struct Packet {
    pub packet_type: PacketType,
    pub content: Vec<u8>,
}

impl Packet {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut content = self.content.iter().map(|c| {*c}).collect::<Vec<u8>>();

        // packet type
        bytes.push(self.packet_type as u8);


        // length data
        bytes.push((content.len() >> 8) as u8);
        bytes.push(content.len() as u8);

        // content
        bytes.append(&mut content);

        bytes
    }
    /// reads only what it needs to from `reader`
    pub fn read_from<R: Read>(reader: &mut R) -> BoxedResult<Packet> {

        // read the first two bytes
        let mut packet_metadata = [0,0,0].to_vec();
        reader.read_exact(&mut packet_metadata)?;

        let size = (packet_metadata[1] as usize) << 8 | (packet_metadata[2] as usize);

        // read the whole packet
        let mut content = vec![0; size];
        reader.read_exact(&mut content)?;

        Ok(Packet { packet_type: PacketType::from(packet_metadata[0]), content })
    }
    /// write a packet to a `writer`
    pub fn write_to<W: Write>(&self, writer: &mut W) -> BoxedResult<()> {
        writer.write_all(&self.to_bytes())?;
        writer.flush()?;

        Ok(())
    }
}