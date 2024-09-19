use crossbeam_channel::unbounded;
use socket2::SockAddr;
use tokio::{net::UdpSocket, sync::Mutex};
use std::{io::{Read, Write}, net::SocketAddr};
use base64::prelude::*;
use log::{error, info, warn};
use std::sync::Arc;
use std::net::Ipv4Addr;
use x25519_dalek::{PublicKey, StaticSecret};
use std::process::Command;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce};

use crate::config::ClientConfiguration;
use crate::udp::{UDPVpnPacket, UDPVpnHandshake, UDPSerializable};
use network_interface::NetworkInterface;
use network_interface::NetworkInterfaceConfig;

pub async fn client_mode(client_config: ClientConfiguration) {
    info!("Starting client...");

    let sock = UdpSocket::bind("0.0.0.0:25565").await.unwrap();
    sock.connect(&client_config.server.endpoint).await.unwrap();

    let mut config = tun2::Configuration::default();
    config.address(&client_config.client.address)
        .netmask("255.255.255.255")
        .destination("10.66.66.1")
        .tun_name("tun0")
        .up();

    let dev = tun2::create(&config).unwrap();
    let (mut dev_reader, mut dev_writer) = dev.split();

    let sock_rec = Arc::new(sock);
    let sock_snd = sock_rec.clone();

    let (tx, rx) = unbounded::<Vec<u8>>();
    let (dx, mx) = unbounded::<Vec<u8>>();

    let cipher_shared = Arc::new(Mutex::new(None));

    tokio::spawn(async move {
        while let Ok(bytes) = rx.recv() {
            //info!("Write to tun {:?}", hex::encode(&bytes));
            dev_writer.write_all(&bytes).unwrap();
        }
    });

    tokio::spawn(async move {
        let mut buf = vec![0; 8192];
        while let Ok(n) = dev_reader.read(&mut buf) {
            dx.send(buf[..n].to_vec()).unwrap();
        }
    });

    let priv_key = BASE64_STANDARD.decode(client_config.client.private_key).unwrap();
    
    let cipher_shared_clone = cipher_shared.clone();
    tokio::spawn(async move {
        let mut buf = vec![0; 4096];

        loop {
            if let Ok(l) = sock_rec.recv(&mut buf).await {
                let mut s_cipher = cipher_shared_clone.lock().await;
                match buf.first() {
                    Some(h) => {
                        match h {
                            0 => {
                                let handshake = UDPVpnHandshake::deserialize(&(buf[..l].to_vec()));
                                let mut k = [0u8; 32];
                                for (&x, p) in handshake.public_key.iter().zip(k.iter_mut()) {
                                    *p = x;
                                }
                                let mut k1 = [0u8; 32];
                                for (&x, p) in priv_key.iter().zip(k1.iter_mut()) {
                                    *p = x;
                                }
                                *s_cipher = Some(StaticSecret::from(k1)
                                    .diffie_hellman(&PublicKey::from(k)));
                            }, // handshake
                            1 => {
                                let wrapped_packet = UDPVpnPacket::deserialize(&(buf[..l].to_vec()));
                                if s_cipher.is_some() {
                                    let aes = Aes256Gcm::new(s_cipher.as_ref().unwrap().as_bytes().into());
                                    let nonce = Nonce::clone_from_slice(&wrapped_packet.nonce);
                                    match aes.decrypt(&nonce, &wrapped_packet.data[..]) {
                                        Ok(decrypted) => { let _ = tx.send(decrypted); },
                                        Err(error) => error!("Decryption error! {:?}", error)
                                    }
                                } else {
                                    warn!("There is no static_secret");
                                }
                            }, // payload
                            2 => info!("Got keepalive packet"),
                            _ => error!("Unexpected header value.")
                        }
                    },
                    None => error!("There is no header.")
                }
                drop(s_cipher);
            }
        }
    });

    let pkey = BASE64_STANDARD.decode(client_config.client.public_key).unwrap();
    let handshake = UDPVpnHandshake{ public_key: pkey, request_ip: client_config.client.address.parse::<Ipv4Addr>().unwrap() };
    let mut nz = 0;
    while nz < 25 {
        sock_snd.send(&handshake.serialize()).await.unwrap();
        nz += 1
    }
    //sock_snd.send(&handshake.serialize()).await.unwrap();

    let s_cipher = cipher_shared.clone();
    loop {
        if let Ok(bytes) = mx.recv() {
            let s_c = s_cipher.lock().await;
            
            if s_c.is_some() {
                let aes = Aes256Gcm::new(s_c.as_ref().unwrap().as_bytes().into());
                let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
                let ciphered_data = aes.encrypt(&nonce, &bytes[..]);
                
                if let Ok(ciphered_d) = ciphered_data {
                    let vpn_packet = UDPVpnPacket{ data: ciphered_d, nonce: nonce.to_vec()};
                    let serialized_data = vpn_packet.serialize();
                    sock_snd.send(&serialized_data).await.unwrap();
                } else {
                    error!("Socket encryption failed.");
                }
            } else {
                warn!("There is no shared_secret in main loop");
            }
        }
    }
}