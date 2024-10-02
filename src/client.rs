use std::{io::{self, BufRead, BufReader, BufWriter, Write}, net::TcpStream, thread};

use dns_lookup::lookup_host;
use rpassword::read_password;
use rsa::{pkcs8::DecodePublicKey, Pkcs1v15Encrypt, RsaPublicKey};

use crate::{shared::{Packet, PacketType, PORT}, BoxedResult};


pub fn start() -> BoxedResult<()> {
    let mut rng = rand::thread_rng();
    let stdin = io::stdin();

    print!("Server URL: ");
    std::io::stdout().flush().unwrap();
    let hostname = stdin.lock().lines().next().unwrap().unwrap();
    let ips: Vec<std::net::IpAddr> = lookup_host(&hostname).unwrap();
    println!("IPs: {ips:?}");

    for ip in ips {
        if let Ok(stream) = TcpStream::connect((ip, PORT)) {
            println!("Connected to the server!");
            let stream = Box::new(stream);
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut writer = BufWriter::new(stream.try_clone().unwrap());
    
            let packet = Packet::read_from(&mut reader)?;
            let pem_text = packet.content.iter().map(|c| *c as char).collect::<String>();
            let pub_key = RsaPublicKey::from_public_key_pem(&pem_text)?;
    
            let mut username_password: Vec<u8> = Vec::new();
    
            print!("Username: ");
            std::io::stdout().flush().unwrap();
            let username = stdin.lock().lines().next().unwrap().unwrap();
            print!("Password: ");
            std::io::stdout().flush().unwrap();
            let password: String = read_password().unwrap();
            username_password.push(username.len() as u8);
            username_password.append(&mut username.as_bytes().to_vec());
            username_password.push(password.len() as u8);
            username_password.append(&mut password.as_bytes().to_vec());
    
            let encrypted_user_info = pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, &username_password)?;
            let packet = Packet { packet_type: PacketType::Login, content: encrypted_user_info };
            packet.write_to(&mut writer)?;
    
            println!("Connected to the Chat!");
    
            thread::spawn(|| {send_messages(writer)});
            read_messages(reader);
    
        }
    }

    println!("Couldn't connect to {}", hostname);

    Ok(())
}

fn send_messages(mut writer: BufWriter<TcpStream>) {
    loop {
        let stdin = io::stdin();
        let message: String = stdin.lock().lines().next().unwrap().unwrap();
        print!("\x1b[A\r");
        let packet = Packet { packet_type: PacketType::SendMessage, content: message.as_bytes().to_vec() };

        packet.write_to(&mut writer).unwrap();
    }
}

fn read_messages(mut reader: BufReader<TcpStream>) {
    loop {
        let packet = Packet::read_from(&mut reader).unwrap();

        println!("{}", packet.content.iter().map(|c| *c as char).collect::<String>());
    }
}