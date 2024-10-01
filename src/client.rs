use std::net::TcpStream;

use bufstream::BufStream;
use rsa::{pkcs8::DecodePublicKey, Pkcs1v15Encrypt, RsaPublicKey};

use crate::{shared::{Packet, PacketType, PORT}, BoxedResult};

pub struct ClientData {
    server_ip: String,
}

pub fn start() -> BoxedResult<()> {
    let mut rng = rand::thread_rng();
    
    let client = ClientData {
        server_ip: "127.0.0.1:".to_owned() + PORT,
    };

    if let Ok(stream) = TcpStream::connect(&client.server_ip) {
        println!("Connected to the server!");
        let mut stream = BufStream::new(stream);

        println!("Reading public key");
        let packet = Packet::read_from(&mut stream)?;
        let pem_text = packet.content.iter().map(|c| *c as char).collect::<String>();
        let pub_key = RsaPublicKey::from_public_key_pem(&pem_text)?;

        println!("Sending account info");
        let mut username_password: Vec<u8> = Vec::new();
        username_password.push(5);
        username_password.append(&mut b"hello".to_vec());
        username_password.push(11);
        username_password.append(&mut b"password123".to_vec());

        let encrypted_user_info = pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, &username_password)?;
        let packet = Packet { packet_type: PacketType::Login, content: encrypted_user_info };
        packet.write_to(&mut stream)?;

        dbg!(packet, pub_key);

    } else {
        println!("Couldn't connect to server...");
    }

    Ok(())
}