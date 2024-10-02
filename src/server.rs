use std::{collections::HashMap, io::{BufReader, BufWriter}, net::{TcpListener, TcpStream}, sync::{Arc, RwLock}, thread, time::Duration};

use rsa::{pkcs8::EncodePublicKey, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

use crate::{shared::{Packet, PacketType, LINEENDING, PORT}, BoxedResult};

type Users = HashMap<String, String>;
type Messages = Vec<Vec<u8>>;
type ArcLock<T> = Arc<RwLock<T>>;

#[derive(Clone)]
struct Keys {
    priv_key: RsaPrivateKey,
    pub_key: RsaPublicKey,
}

pub fn start() -> BoxedResult<()> {

    let mut rng = rand::thread_rng();
    let bits = 2048;

    println!("Generating RSA keys...");
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pub_key = RsaPublicKey::from(&priv_key);
    println!("Done");

    let listener = TcpListener::bind(("0.0.0.0".to_owned(), PORT))?;

    let keys = Keys { priv_key, pub_key };
    let users: ArcLock<Users> = Arc::new(RwLock::new(HashMap::new()));
    let messages: ArcLock<Messages> = Arc::new(RwLock::new(Vec::new()));

    for stream in listener.incoming() {
        if let Ok(stream) = stream {
            let keys = keys.clone();
            let users = Arc::clone(&users);
            let messages = Arc::clone(&messages);
            std::thread::spawn(move || {
                match handle_connection(Box::new(stream), &keys, users, messages) {
                    Ok(_) => (),
                    Err(e) => {println!("handle_connection() failed: {e:?}")},
                }
            });
        } else if let Err(e) = stream {
            println!("Error: {e}");
        } else {
            unreachable!()
        }
    }

    Ok(())
}
fn handle_connection(tcpstream: Box<TcpStream>, keys: &Keys, users: ArcLock<Users>, messages: ArcLock<Messages>) -> BoxedResult<()> {
    // let mut stream = BufStream::new(tcpstream);
    let mut writer = BufWriter::new(tcpstream.try_clone().unwrap());
    let mut reader = BufReader::new(tcpstream.try_clone().unwrap());

    let pub_key_packet = Packet {
        packet_type: PacketType::PubKey,
        content: keys.pub_key.to_public_key_pem(LINEENDING)?.into()
    };

    pub_key_packet.write_to(&mut writer)?;

    let packet = Packet::read_from(&mut reader)?;

    if let PacketType::Login = packet.packet_type {
        let decrypted_message = keys.priv_key.decrypt(Pkcs1v15Encrypt, &packet.content)?;
    
        let username = decrypted_message[1..].iter().take(decrypted_message[0] as usize).map(|c| *c as char).collect::<String>();
        let password = decrypted_message[username.len()+2..].iter().take(decrypted_message[username.len()+1] as usize).map(|c| *c as char).collect::<String>();

        let new_user: bool;

        {
            let user_lock = users.read().unwrap();

            new_user = !user_lock.contains_key(&username);
        }
        {
            let mut user_lock = users.write().unwrap();
            if new_user {
                user_lock.insert(username.clone(), password);
                println!("Created new user: {username}");
            } else {
                if *user_lock.get(&username).unwrap() != password {
                    println!("Login atempt failed for user: {username}");
                    return Ok(());
                } else {
                    println!("Login atempt valid for user: {username}");
                }
            }
        }
        let arc_clone = Arc::clone(&messages);
        thread::spawn(|| {let _ = message_sender(writer, arc_clone);});
        let arc_clone = Arc::clone(&messages);
        thread::spawn(|| {let _ = message_reader(reader, arc_clone, username);});
    }

    Ok(())
}

fn message_sender(mut writer: BufWriter<TcpStream>, messages: ArcLock<Messages>) -> BoxedResult<()> {
    let mut message_index: usize = 0;
    loop {
        {
            let message_lock = messages.read().unwrap();
            for message in message_index..message_lock.len() {
                let content = &message_lock[message];
                let packet = Packet { packet_type: PacketType::SendMessage, content: content.to_vec() };
        
                packet.write_to(&mut writer)?;
            }
            message_index = message_lock.len();
        }

        thread::sleep(Duration::new(1, 0));
    }
}

fn message_reader(mut reader: BufReader<TcpStream>, messages: ArcLock<Messages>, username: String) -> BoxedResult<()> {
    let username = username.as_bytes().to_vec();
    let mut new_message = username.clone();
    new_message.append(&mut b" has joined!".to_vec());
    {
        let mut message_lock = messages.write().unwrap();
        message_lock.push(new_message);
    }
    loop {
        let mut packet = match Packet::read_from(&mut reader) {
            Ok(x) => x,
            Err(_) => {
                let mut new_message = username.clone();
                new_message.append(&mut b" has left!".to_vec());
                {
                    let mut message_lock = messages.write().unwrap();
                    message_lock.push(new_message);
                }
                return Ok(());
            },
        };

        match packet.packet_type {
            PacketType::SendMessage => {
                let mut message_lock = messages.write().unwrap();
                let mut new_message = username.clone();
                new_message.append(&mut b" > ".to_vec());
                new_message.append(&mut packet.content);
                message_lock.push(new_message);
            },
            PacketType::Disconnect => return Ok(()),
            _ => (),
        }

    }
}