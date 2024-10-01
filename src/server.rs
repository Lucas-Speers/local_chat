use std::{collections::HashMap, net::{TcpListener, TcpStream}, sync::{Arc, RwLock}};

use bufstream::BufStream;
use rsa::{pkcs8::EncodePublicKey, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

use crate::{shared::{Packet, PacketType, LINEENDING, PORT}, BoxedResult};

type Users = HashMap<String, String>;
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

    let listener = TcpListener::bind("127.0.0.1:".to_owned() + PORT)?;

    let keys = Keys { priv_key, pub_key };
    let users: ArcLock<Users> = Arc::new(RwLock::new(HashMap::new()));

    for stream in listener.incoming() {
        if let Ok(stream) = stream {
            let keys = keys.clone();
            let users = Arc::clone(&users);
            std::thread::spawn(move || {
                match handle_connection(stream, &keys, users) {
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
fn handle_connection(stream: TcpStream, keys: &Keys, users: ArcLock<Users>) -> BoxedResult<()> {
    let mut stream = BufStream::new(&stream);

    let pub_key_packet = Packet {
        packet_type: PacketType::PubKey,
        content: keys.pub_key.to_public_key_pem(LINEENDING)?.into()
    };

    pub_key_packet.write_to(&mut stream)?;

    let packet = Packet::read_from(&mut stream)?;

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
                println!("Created new user: {username}");
                user_lock.insert(username, password);
            } else {
                if *user_lock.get(&username).unwrap() != password {
                    println!("Login atempt failed for user: {username}");
                    return Ok(());
                } else {
                    println!("Login atempt valid for user: {username}");
                    // connected sucsesfully
                }
            }
        }
    }

    Ok(())
}