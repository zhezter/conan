use arti_client::{BootstrapBehavior, TorClient, TorClientConfig, config::CfgPath};
use ed25519_dalek::ed25519::signature::rand_core::OsRng;
use futures::{StreamExt, stream::BoxStream};
use safelog::DisplayRedacted;
use std::{
    collections::HashMap,
    error::Error,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::broadcast,
};
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::{HsNickname, OnionServiceConfig, RendRequest, RunningOnionService};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::{
    comm::enums::IPCRes,
    config::parse_config,
    debug,
    entities::slave::Slave,
    msg::{Msg, PeerStatus},
    operations::{edhverify, x25519_handshake},
};

pub struct Manager {
    tor_client: Arc<TorClient<tor_rtcompat::PreferredRuntime>>,
    /// NOTE: Only for assigning to `Slaves`, not to be used by manager itself
    response_sender: broadcast::Sender<(u8, Msg)>,

    stream: Option<BoxStream<'static, RendRequest>>,
    _service: Arc<RunningOnionService>,

    /// Channel for sending message to Master
    pub msg_sender: broadcast::Sender<IPCRes>,
    /// Used for receiving messages from Slaves and transferring them to Master
    pub response_receiver: broadcast::Receiver<(u8, Msg)>,
    /// `HashMap` for tracking active peers
    pub peers: Arc<Mutex<HashMap<u8, Slave>>>,
}

impl Manager {
    /// # Errors
    pub async fn create(msg_sender: broadcast::Sender<IPCRes>) -> Result<Self, Box<dyn Error>> {
        let config = parse_config()?;
        let arti_store = config.arti_key_store;
        let mut tor_config_builder = TorClientConfig::builder();
        let stream_timeout_config = tor_config_builder.stream_timeouts();
        // setting timeout to 20 secs bcoz we'd rather not wait 60 secs when its destined to fail
        stream_timeout_config.connect_timeout(Duration::from_secs(20));
        let storage_builder = tor_config_builder.storage();
        let state_path = CfgPath::new(arti_store.clone());
        let cache_path = CfgPath::new(config.cache_path);
        storage_builder.cache_dir(cache_path).state_dir(state_path);
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
        let (response_sender, response_receiver) = broadcast::channel::<(u8, Msg)>(100);

        Ok(Self {
            tor_client,
            peers: Arc::new(Mutex::new(HashMap::new())),
            stream: Some(request_stream.boxed()),
            _service: service,
            msg_sender,
            response_receiver,
            response_sender,
        })
    }

    /// # Errors
    /// # Panics
    pub fn init_server(&mut self) -> Result<(), Box<dyn Error>> {
        debug!("Initializing Server.");
        let mut stream = self.stream.take().unwrap();

        // spawn a thread for handling connections from network
        let msg_sender = self.msg_sender.clone();
        let response_sender = self.response_sender.clone();
        let peers = Arc::clone(&self.peers);
        tokio::spawn(async move {
            let msg_sender = msg_sender.clone();
            let response_sender = response_sender.clone();
            let peers = Arc::clone(&peers);
            loop {
                while let Some(rendreq) = stream.next().await {
                    let msg_sender = msg_sender.clone();
                    let response_sender = response_sender.clone();
                    let peers = Arc::clone(&peers);
                    println!("Client Detected.");
                    tokio::spawn(async move {
                        match rendreq.accept().await {
                            Ok(mut stream) => {
                                while let Some(strreq) = stream.next().await {
                                    let msg_sender = msg_sender.clone();
                                    let response_sender = response_sender.clone();
                                    match strreq.accept(Connected::new_empty()).await {
                                        Ok(stream) => {
                                            let (reader, writer) = tokio::io::split(stream);
                                            let mut conn = Slave {
                                                reader: Some(reader),
                                                writer,
                                                msg_sender,
                                                response_sender,
                                                shared_secret_key: Arc::new(RwLock::new([0u8; 32])),
                                            };
                                            if let Err(e) = conn.connect_as_listener().await {
                                                eprintln!("Cannot connect as listener.\n{e}");
                                                continue;
                                            }
                                            if conn.spawn_communication().is_ok() {
                                                let mut guard = peers.lock().unwrap();
                                                #[allow(clippy::cast_possible_truncation)]
                                                let idx = guard.len() as u8;
                                                guard.insert(idx, conn);
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

    /// Connects to Peer's Tor Address as a dialer (Seeking connection)
    /// # Errors
    /// # Panics
    pub async fn connect_as_dialer(
        &mut self,
        peer_addr: (String, u16),
    ) -> Result<PeerStatus, Box<dyn Error>> {
        debug!("Connecting to peer...");
        let stream = loop {
            match self.tor_client.connect(&peer_addr).await {
                Ok(s) => break s,
                Err(e) => eprintln!("Error while connecting: {e}"),
            }
        };
        let (mut reader, mut writer) = tokio::io::split(stream);
        let size = reader.read_u16().await? as usize;
        println!("recommended size: {size}");
        let mut buf = vec![0u8; size];
        let size = reader.read_exact(&mut buf).await?;

        let de_msg = Msg::from_bytes(&buf[..size]);
        debug!("received msg: {:?}", de_msg);

        let local_private_key = EphemeralSecret::random_from_rng(OsRng);
        let mut remote_public_key = None;
        println!("Performing X25519 Handshake.");
        x25519_handshake(&mut remote_public_key, &peer_addr, de_msg)?;
        let local_public_key = PublicKey::from(&local_private_key);
        let msg = Msg::PublicKey(local_public_key.to_bytes());
        debug!("SENDING msg:\n{:?}", msg);
        let msg_bytes = msg.to_vec();

        #[allow(clippy::cast_possible_truncation)]
        writer.write_u16(msg_bytes.len() as u16).await?;
        writer.write_all(&msg_bytes).await?;
        writer.flush().await?;
        println!("Handshake Complete. Performing Elliptical Diffie-Hellman key exchange.");
        // At this point, we know remote_public_key is filled
        let Some(remote_public_key) = remote_public_key else {
            return Err("Remote Public Key not set.".into());
        };
        let mut shared_secret_key = None;
        edhverify(
            &mut writer,
            local_private_key,
            remote_public_key,
            &mut shared_secret_key,
        )
        .await?;
        let msg_sen = self.msg_sender.clone();
        let response_sender = self.response_sender.clone();
        let Some(shared_secret_key) = shared_secret_key else {
            return Err("Couldn't get Shared Secret Key.".into());
        };
        let mut conn = Slave {
            reader: Some(reader),
            writer,
            msg_sender: msg_sen,
            response_sender,
            shared_secret_key: Arc::new(RwLock::new(shared_secret_key)),
        };
        _ = conn.spawn_communication();
        {
            let mut peers = self.peers.lock().unwrap();
            #[allow(clippy::cast_possible_truncation)]
            let idx = peers.len() as u8 + 1;
            peers.insert(idx, conn);
        }
        println!("Exchange Complete..");
        Ok(PeerStatus::Connected)
    }

    /// Used to setup Slave to Master communication Pipeline
    /// # Errors
    pub fn setup_slave_communication(&mut self) -> Result<(), Box<dyn Error>> {
        let mut rec = self.response_receiver.resubscribe();
        let sen = self.msg_sender.clone();
        tokio::spawn(async move {
            while let Ok(msg) = rec.recv().await {
                let final_msg = match msg.1 {
                    Msg::Text(text) => IPCRes::Text(msg.0, text),
                    _ => {
                        continue;
                    }
                };
                _ = sen.send(final_msg);
            }
        });
        Ok(())
    }
}
