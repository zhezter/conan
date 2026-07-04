pub mod comm;
pub mod config;
pub mod constants;
pub mod msg;
pub mod operations;
pub mod requests;
#[cfg(test)]
pub mod tests;
use arti_client::{BootstrapBehavior, DataStream, TorClient, TorClientConfig, config::CfgPath};
use bincode::config as cfg;
use constants::SELF_PORT;
use ed25519_dalek::{
    Signature, Signer, Verifier, VerifyingKey, ed25519::signature::rand_core::OsRng,
};
use futures::{StreamExt, stream::BoxStream};
use msg::{Msg, PeerStatus};
use safelog::DisplayRedacted;
use std::{
    collections::HashMap,
    error::Error,
    str::FromStr,
    sync::{Arc, Mutex, RwLock, mpsc},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    sync::broadcast,
};
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::{HsId, HsNickname, OnionServiceConfig, RendRequest, RunningOnionService};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::{
    config::parse_config,
    msg::Internal,
    operations::{decrypt, encrypt, signing_key},
};

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        {
            println!("[DEBUG] {}", format_args!($($arg)*));
        }
    };
}

pub struct Handler {
    /// Self onion Address
    pub self_addr: Option<(HsId, u16)>,
    /// Sender Channel for internal Commands
    pub worker_sen: mpsc::Sender<Internal>,
}

pub struct Worker {
    pub tor_client: Arc<TorClient<tor_rtcompat::PreferredRuntime>>,
    /// Channel for receiving tasks
    pub worker_rx: mpsc::Receiver<Internal>,
    pub stream: Option<BoxStream<'static, RendRequest>>,
    pub service: Arc<RunningOnionService>,
    /// HashMap for tracking active peers
    pub peers: Arc<Mutex<HashMap<u8, PeerConnection>>>,
}

pub struct PeerConnection {
    reader: ReadHalf<DataStream>,
    writer: WriteHalf<DataStream>,
    /// Shared secret key after diffie helmann exchange
    pub shared_secret_key: Arc<RwLock<[u8; 32]>>,
}

impl Handler {
    pub fn build(self_addr: Option<(HsId, u16)>, worker_sen: mpsc::Sender<Internal>) -> Self {
        Self {
            worker_sen,
            self_addr,
        }
    }
}

impl Worker {
    pub async fn create(worker_rx: mpsc::Receiver<Internal>) -> Result<Self, Box<dyn Error>> {
        let config = parse_config()?;
        let arti_store = config.arti_key_store;
        let mut tor_config_builder = TorClientConfig::builder();
        let config_path = arti_store.to_string();
        let storage_builder = tor_config_builder.storage();
        let cfgpath = CfgPath::new(config_path.clone());
        storage_builder.state_dir(cfgpath);
        let tor_config = tor_config_builder.build()?;

        debug!("Starting Server...");
        let tor_client = TorClient::builder()
            .bootstrap_behavior(BootstrapBehavior::OnDemand)
            .config(tor_config)
            .create_bootstrapped()
            .await?;

        let nickname = HsNickname::new("conan-daemon".to_string())?;
        let svc_config = OnionServiceConfig::builder().nickname(nickname).build()?;
        let Ok(Some((service, request_stream))) = tor_client.launch_onion_service(svc_config)
        else {
            return Err("Could not launch onion service...".into());
        };

        let hsid: tor_hsservice::HsId = match service.onion_address() {
            Some(s) => s,
            None => return Err("No HsId found.".into()),
        };
        println!("Server Address: {}", hsid.display_unredacted());

        Ok(Self {
            tor_client,
            peers: Arc::new(Mutex::new(HashMap::new())),
            stream: Some(request_stream.boxed()),
            service,
            worker_rx,
        })
    }

    pub fn init_server(&mut self) -> Result<(), Box<dyn Error>> {
        debug!("Initializing Server.");
        let mut stream = self.stream.take().unwrap();

        let peers = Arc::clone(&self.peers);
        // spawn a thread for handling connections from network
        tokio::spawn(async move {
            let peers = Arc::clone(&peers);
            loop {
                while let Some(rendreq) = stream.next().await {
                    println!("Client Detected.");
                    let peers = Arc::clone(&peers);
                    tokio::spawn(async move {
                        match rendreq.accept().await {
                            Ok(mut stream) => {
                                let peers = Arc::clone(&peers);
                                while let Some(strreq) = stream.next().await {
                                    match strreq.accept(Connected::new_empty()).await {
                                        Ok(stream) => {
                                            let mut guard = peers.lock().unwrap();
                                            let (reader, writer) = tokio::io::split(stream);
                                            let idx = guard.len() as u8;
                                            guard.insert(
                                                idx,
                                                PeerConnection {
                                                    reader,
                                                    writer,
                                                    shared_secret_key: Arc::new(RwLock::new(
                                                        [0u8; 32],
                                                    )),
                                                },
                                            );
                                            // if let Err(e) = self.handle_stream().await {
                                            //     eprintln!("CLient Handling Error: {e}");
                                            // }
                                        }
                                        Err(e) => {
                                            eprintln!("Error in connecting to peer: {e}");
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("Failed to complete handshake.\n{e}");
                            }
                        }
                    });
                }
            }
        });
        Ok(())
    }

    pub async fn connect_as_dialer(
        &mut self,
        peer_addr: (String, u16),
    ) -> Result<PeerStatus, Box<dyn Error>> {
        let stream = self.tor_client.connect(&peer_addr).await?;
        let (mut reader, mut writer) = tokio::io::split(stream);
        let mut buf = [0u8; 4096];
        let size = reader.read(&mut buf).await?;

        let (de_msg, _) =
            bincode::serde::decode_from_slice::<Msg, _>(&buf[..size], cfg::standard())?;

        let local_private_key = EphemeralSecret::random_from_rng(OsRng);
        let mut remote_public_key = None;
        println!("Performing X25519 Handshake.");
        self.x25519_handshake(&mut remote_public_key, peer_addr, de_msg)?;

        let local_public_key = PublicKey::from(&local_private_key);
        let msg = Msg::PublicKey(*local_public_key.as_bytes());
        let msg_bytes = bincode::serde::encode_to_vec(msg, cfg::standard())?;
        writer.write_all(&msg_bytes).await?;
        writer.flush().await?;
        println!("Handshake Complete. Performing Eliptical Diffie-Helmann key exchange.");
        // At this point, we know remote_public_key is filled
        if let Some(remote_public_key) = remote_public_key {
            let mut shared_secret_key = None;
            self.edhverify(
                &mut writer,
                local_private_key,
                remote_public_key,
                &mut shared_secret_key,
            )
            .await?;
            {
                let mut peers = self.peers.lock().unwrap();
                let idx = peers.len() as u8;
                peers.insert(
                    idx,
                    PeerConnection {
                        reader,
                        writer,
                        shared_secret_key: Arc::new(RwLock::new(shared_secret_key.unwrap())),
                    },
                );
            }
            println!("Exchange Complete..");
            Ok(PeerStatus::Connected)
        } else {
            println!("Did not receive remote public key.");
            Ok(PeerStatus::NotFound)
        }
    }

    fn x25519_handshake(
        &mut self,
        remote_public_key: &mut Option<PublicKey>,
        peer_addr: (String, u16),
        msg: Msg,
    ) -> Result<(), Box<dyn Error>> {
        if let Msg::SignedAndPublicKey(signature, claimed_remote_public_key) = msg {
            let hsid = HsId::from_str(&peer_addr.0)?;
            let hsid_bytes = hsid.as_ref();
            let verifying_key = VerifyingKey::from_bytes(hsid_bytes)?;
            let signature: [u8; 64] = match signature.try_into() {
                Ok(s) => s,
                Err(e) => {
                    return Err(
                        format!("Cannot convert signature to Array, len {}", e.len()).into(),
                    );
                }
            };
            let signature = Signature::from_bytes(&signature);
            verifying_key.verify(&claimed_remote_public_key, &signature)?;
            *remote_public_key = Some(PublicKey::from(claimed_remote_public_key));
        }
        Ok(())
    }

    async fn edhverify(
        &mut self,
        writer: &mut WriteHalf<DataStream>,
        local_private_key: EphemeralSecret,
        remote_public_key: PublicKey,
        ssk: &mut Option<[u8; 32]>,
    ) -> Result<(), Box<dyn Error>> {
        let local_public_key = PublicKey::from(&local_private_key);
        let shared_secret_key = local_private_key.diffie_hellman(&remote_public_key);
        let mut buf = [0u8; 4096];
        let msg_size = bincode::serde::encode_into_slice(
            Msg::PublicKey(*local_public_key.as_bytes()),
            &mut buf,
            cfg::standard(),
        )?;
        writer.write_all(&buf[..msg_size]).await?;
        writer.flush().await?;
        *ssk = Some(*shared_secret_key.as_bytes());

        Ok(())
    }
}

impl PeerConnection {
    pub async fn connect_as_listener(&mut self) -> Result<(), Box<dyn Error>> {
        let local_private_key = EphemeralSecret::random_from_rng(OsRng);
        let local_public_key = PublicKey::from(&local_private_key);
        let signing_key = signing_key()?;
        let signature = signing_key.sign(local_public_key.as_bytes());
        let msg = Msg::SignedAndPublicKey(signature.to_vec(), *local_public_key.as_bytes());
        let payload = bincode::serde::encode_to_vec(msg, cfg::standard())?;
        debug!("Sending Signature & Public Key to peer.");
        self.writer.write_all(&payload).await?;
        let mut buf = [0u8; 4096];
        debug!("Reading peer's public key.");
        let size = self.reader.read(&mut buf).await?;
        debug!("Parsing peer's public key.");
        let (recv_msg, _) =
            bincode::serde::decode_from_slice::<Msg, _>(&buf[..size], cfg::standard())?;

        if let Msg::PublicKey(remote_public_key) = recv_msg {
            let rpk = PublicKey::from(remote_public_key);
            let shared_secret_key = local_private_key.diffie_hellman(&rpk);
            *self.shared_secret_key.write().unwrap() = *shared_secret_key.as_bytes();
        }
        Ok(())
    }
}

impl PeerConnection {
    /// Creates a brand new circuit with Tor Relays and returns a `PeerConnection`
    /// that can be later used for chatting
    ///
    /// # Errors
    pub async fn create(arti_store: &str) -> Result<Self, Box<dyn Error>> {
        let mut tor_config_builder = TorClientConfig::builder();
        let config_path = arti_store.to_string();
        let storage_builder = tor_config_builder.storage();
        let cfgpath = CfgPath::new(config_path.clone());
        storage_builder.state_dir(cfgpath);
        let tor_config = tor_config_builder.build()?;

        debug!("Starting Server...");
        let tor_client = TorClient::builder()
            .bootstrap_behavior(BootstrapBehavior::OnDemand)
            .config(tor_config)
            .create_bootstrapped()
            .await?;

        let nickname = HsNickname::new("conan-daemon".to_string())?;
        let svc_config = OnionServiceConfig::builder().nickname(nickname).build()?;
        let Ok(Some((service, request_stream))) = tor_client.launch_onion_service(svc_config)
        else {
            return Err("Could not launch onion service...".into());
        };
        let hsid: tor_hsservice::HsId = match service.onion_address() {
            Some(s) => s,
            None => return Err("No HsId found.".into()),
        };
        println!("Server Address: {}", hsid.display_unredacted());
        let (rem_sen, rem_rec) = tokio::sync::broadcast::channel::<Vec<u8>>(100);
        let (loc_sen, loc_rec) = tokio::sync::broadcast::channel::<Vec<u8>>(100);

        Ok(Self {
            peer_addr: None,
            self_addr: Some((hsid, SELF_PORT)),
            service: Some(service),
            stream: Some(request_stream.boxed()),
            rem_sen,
            rem_rec,
            loc_sen,
            loc_rec,
            shared_secret_key: Arc::new(RwLock::new([0u8; 32])),
            tor_client,
            peers: Arc::new(HashMap::new()),
        })
    }

    /// Used to listen to incoming messages from peer and append it to `msg_rx`
    /// # Errors
    ///
    /// # Panics
    pub fn init_server(&mut self) -> Result<(), Box<dyn Error>> {
        debug!("Initializing Server.");
        let mut stream = self.stream.take().ok_or("No stream assigned yet.")?;
        // accept connections and
        let rem_sx_clone = self.rem_sen.clone();
        let loc_rx_clone = self.loc_rec.resubscribe();

        // spawn a thread for handling connections from network
        tokio::spawn(async move {
            loop {
                while let Some(rendreq) = stream.next().await {
                    println!("Client Detected.");
                    let rem_sx_clone = rem_sx_clone.clone();
                    let loc_rx_clone = loc_rx_clone.resubscribe();
                    let peers = Arc::clone(&self.peers);
                    tokio::spawn(async move {
                        match rendreq.accept().await {
                            Ok(mut stream) => {
                                while let Some(strreq) = stream.next().await {
                                    match strreq.accept(Connected::new_empty()).await {
                                        Ok(stream) => {
                                            let (reader, writer) = tokio::io::split(stream);
                                            let idx = peers.len() as u32;
                                            peers.insert(idx + 1, Arc::new((reader, writer)));
                                            if let Err(e) = self.handle_stream().await {
                                                eprintln!("CLient Handling Error: {e}");
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!("Error in connecting to peer: {e}");
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("Failed to complete handshake.\n{e}");
                            }
                        }
                    });
                }
            }
        });

        Ok(())
    }

    #[inline]
    async fn connect_with_addr(
        &mut self,
        peer_addr: (HsId, u16),
    ) -> Result<(), Box<arti_client::Error>> {
        let tuple = (peer_addr.0.display_unredacted().to_string(), peer_addr.1);
        self.peer_addr = Some(tuple.clone());
        loop {
            if let Err(e) = self.tor_client.connect(tuple.clone()).await {
                eprintln!("Connection err: {e}");
            } else {
                break;
            }
            println!("Retrying...");
        }
        Ok(())
    }

    /// Used to connect to listener
    ///
    /// # Errors
    ///
    pub async fn connect_as_dialer(
        &mut self,
        peer_addr: (HsId, u16),
    ) -> Result<PeerStatus, Box<dyn Error>> {
        println!("Connecting to peer...");
        self.connect_with_addr(peer_addr).await?;
        println!("Connected. Verifying integrity.");

        let rem_sen = self.rem_sen.clone();
        let loc_rec = self.loc_rec.resubscribe();

        tokio::spawn(async move {});
        let msg = self.recv_raw().await?;
        debug!("first msg: {msg:?}");

        let (de_msg, _) = bincode::serde::decode_from_slice::<Msg, _>(&msg, cfg::standard())?;
        let local_private_key = EphemeralSecret::random_from_rng(OsRng);
        let mut remote_public_key = None;
        println!("Performing X25519 Handshake.");
        self.x25519_handshake(&mut remote_public_key, de_msg)?;

        let local_public_key = PublicKey::from(&local_private_key);
        let msg = Msg::PublicKey(*local_public_key.as_bytes());
        let msg_bytes = bincode::serde::encode_to_vec(msg, cfg::standard())?;
        self.send_raw(msg_bytes)?;
        println!("Handshake Complete. Performing Eliptical Diffie-Helmann key exchange.");

        // At this point, we know remote_public_key is filled
        if let Some(remote_public_key) = remote_public_key {
            self.edhverify(local_private_key, remote_public_key)?;
            println!("Exchange Complete..");
            Ok(PeerStatus::Connected)
        } else {
            println!("Did not receive remote public key.");
            Ok(PeerStatus::NotFound)
        }
    }

    /// Use to send bytes to `local_msg_sx` as is
    ///
    /// # Errors
    /// Follows `[tokio::sync::mpsc::SendError<Vec<u8>>]`
    #[inline]
    pub fn send_raw(&self, msg: Vec<u8>) -> Result<usize, broadcast::error::SendError<Vec<u8>>> {
        self.loc_sen.send(msg)
    }

    /// Used to send messages `[msg::Msg]` to connected peer
    ///
    /// # Errors
    /// # Panics
    pub fn send(&self, msg: Msg) -> Result<(), Box<dyn Error>> {
        let msg = bincode::serde::encode_to_vec(msg, cfg::standard())?;
        let ssk = self.shared_secret_key.read().unwrap().to_owned();
        let encrypted_msg = encrypt(&ssk, &msg)?;
        self.send_raw(encrypted_msg)?;
        Ok(())
    }

    /// Recieves data from peer as is.
    /// # Errors
    #[inline]
    pub async fn recv_raw(&mut self) -> Result<Vec<u8>, broadcast::error::RecvError> {
        self.rem_rec.recv().await
    }

    /// Recieves decrypted `[Msg::msg]` from peer.
    ///
    /// # Errors
    /// Errors from possible corrupted decryption
    ///
    /// # Panics
    pub async fn recv(&mut self) -> Result<Option<Msg>, Box<dyn Error>> {
        let encr_msg = match self.recv_raw().await {
            Ok(s) => s,
            Err(e) => return Err(e.into()),
        };
        let ssk = self.shared_secret_key.read().unwrap().to_owned();
        let msg = decrypt(&ssk, &encr_msg)?;
        let (decoded, _) = bincode::serde::decode_from_slice(&msg, cfg::standard())?;
        Ok(Some(decoded))
    }

    /// Stage 1 of the 2 Stage Encryption process after tor connection
    /// Use this when reaching out to another peer
    ///
    /// # Errors
    fn x25519_handshake(
        &mut self,
        remote_public_key: &mut Option<PublicKey>,
        msg: Msg,
    ) -> Result<(), Box<dyn Error>> {
        if let Msg::SignedAndPublicKey(signature, claimed_remote_public_key) = msg {
            let hsid_str = match self.peer_addr.as_ref() {
                Some(s) => &s.0,
                None => return Err("No Peer Address found.".into()),
            };
            let hsid = HsId::from_str(hsid_str)?;
            let hsid_bytes = hsid.as_ref();
            let verifying_key = VerifyingKey::from_bytes(hsid_bytes)?;
            let signature: [u8; 64] = match signature.try_into() {
                Ok(s) => s,
                Err(e) => {
                    return Err(
                        format!("Cannot convert signature to Array, len {}", e.len()).into(),
                    );
                }
            };
            let signature = Signature::from_bytes(&signature);
            verifying_key.verify(&claimed_remote_public_key, &signature)?;
            *remote_public_key = Some(PublicKey::from(claimed_remote_public_key));
        }
        Ok(())
    }

    /// Last Stage of 2 stage encryption
    /// Verifies the key using Eliptical diffie-helmann, and saves it in memory for further use along the chat
    ///
    /// # Errors
    ///
    /// # Panics
    pub fn edhverify(
        &mut self,
        local_private_key: EphemeralSecret,
        remote_public_key: PublicKey,
    ) -> Result<(), Box<dyn Error>> {
        let local_public_key = PublicKey::from(&local_private_key);
        let shared_secret_key = local_private_key.diffie_hellman(&remote_public_key);
        self.send(Msg::PublicKey(*local_public_key.as_bytes()))?;
        *self.shared_secret_key.write().unwrap() = *shared_secret_key.as_bytes();

        Ok(())
    }
    /// # Errors
    /// # Panics
    pub async fn handle_stream(&mut self, idx: u8) -> Result<(), Box<dyn Error>>
// where
        // T: AsyncReadExt + Unpin + Send + 'static,
        // S: AsyncWriteExt + Unpin + Send + 'static,
    {
        let retries = 5;

        for _ in 0..retries {
            if let Err(e) = self.connect_as_listener().await {
                eprintln!("Listener Error: {e:#?}");
            } else {
                break;
            }
            eprintln!("Retrying...");
        }
        debug!("Secret key set.");

        // let Some(cur_stream) = self.peers.get(&(idx as u32)) else {
        //     return Err(format!("No Stream ffound with index: {idx}").into());
        // };
        // let rem_sx = self.rem_sen.clone();
        // let stream_arc = Arc::clone(&cur_stream);
        // let reader = stream_arc.0;
        // // We spawn a tokio thread to listen for incoming messages from peer
        // // we convert it to clear message and push it to remote_msg_sx
        // tokio::spawn(async move {
        //     let mut final_buf = vec![];
        //     let mut buf = [0u8; 4096];
        //     loop {
        //         match reader.read(&mut buf).await {
        //             Ok(0) => {
        //                 if final_buf.is_empty() {
        //                     continue;
        //                 }
        //                 _ = rem_sx.send(final_buf.clone());
        //                 final_buf.clear();
        //             }
        //             Ok(size) => {
        //                 println!("received buf: {:?}", &buf[..size]);
        //                 final_buf.extend_from_slice(&buf[..size]);
        //             }
        //             Err(e) => {
        //                 eprintln!("Error found: {e}");
        //             }
        //         }
        //     }
        // });
        // let mut writer = stream_arc.1;
        // let mut loc_rx = self.loc_rec.resubscribe();
        //
        // // We spawn this tread to listen for messages that the user sends to peer
        // // convert it excrypted message, and send it over the writer
        // tokio::spawn(async move {
        //     while let Ok(cmd) = loc_rx.recv().await {
        //         let encoded = bincode::serde::encode_to_vec(cmd, cfg::standard()).unwrap();
        //         _ = writer.write_all(&encoded).await;
        //         _ = writer.flush().await;
        //     }
        // });
        Ok(())
    }
    /// Used to connect to dialer
    ///
    /// # Errors
    /// # Panics
    pub async fn connect_as_listener(&mut self, idx: u8) -> Result<(), Box<dyn Error>>
// where
    //     T: AsyncReadExt + Unpin,
    //     S: AsyncWriteExt + Unpin,
    {
        let Some(stream_arc) = self.peers.get(&(idx as u32)) else {
            return Err(format!("No Stream found for idx: {idx}").into());
        };
        let stream = Arc::clone(&stream_arc);
        let mut reader = &stream.0;
        let mut writer = &stream.1;
        let local_private_key = EphemeralSecret::random_from_rng(OsRng);
        let local_public_key = PublicKey::from(&local_private_key);
        let signing_key = signing_key()?;
        let signature = signing_key.sign(local_public_key.as_bytes());
        let msg = Msg::SignedAndPublicKey(signature.to_vec(), *local_public_key.as_bytes());
        let payload = bincode::serde::encode_to_vec(msg, cfg::standard())?;
        debug!("Sending Signature & Public Key to peer.");
        writer.write_all(&payload).await?;
        let mut buf = [0u8; 4096];
        debug!("Reading peer's public key.");
        let size = reader.read(&mut buf).await?;
        debug!("Parsing peer's public key.");
        let (recv_msg, _) =
            bincode::serde::decode_from_slice::<Msg, _>(&buf[..size], cfg::standard())?;

        if let Msg::PublicKey(remote_public_key) = recv_msg {
            let rpk = PublicKey::from(remote_public_key);
            let shared_secret_key = local_private_key.diffie_hellman(&rpk);
            *self.shared_secret_key.write().unwrap() = *shared_secret_key.as_bytes();
        }
        Ok(())
    }
}
