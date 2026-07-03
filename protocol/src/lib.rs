pub mod comm;
pub mod constants;
pub mod msg;
pub mod operations;
pub mod requests;
#[cfg(test)]
pub mod tests;
use arti_client::{BootstrapBehavior, TorClient, TorClientConfig, config::CfgPath};
use bincode::config;
use constants::SELF_PORT;
use ed25519_dalek::{
    Signature, Signer, Verifier, VerifyingKey, ed25519::signature::rand_core::OsRng,
};
use futures::{StreamExt, stream::BoxStream};
use msg::{Msg, PeerStatus};
use safelog::DisplayRedacted;
use std::{
    env,
    error::Error,
    str::FromStr,
    sync::{Arc, RwLock},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::broadcast,
};
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::{HsId, HsNickname, OnionServiceConfig, RendRequest, RunningOnionService};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::{
    constants::{ARTI_KEYSTORE, ARTI_PRIVATE_KEY},
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

pub struct PeerConnection {
    pub peer_addr: Option<(String, u16)>,
    pub self_addr: Option<(HsId, u16)>,
    pub service: Option<Arc<RunningOnionService>>,
    pub stream: Option<BoxStream<'static, RendRequest>>,
    /// Shared secret key after diffie helmann exchange
    shared_secret_key: Arc<RwLock<[u8; 32]>>,

    tor_client: Option<Arc<TorClient<tor_rtcompat::PreferredRuntime>>>,
    rem_sen: broadcast::Sender<Vec<u8>>,
    rem_rec: broadcast::Receiver<Vec<u8>>,
    loc_sen: broadcast::Sender<Vec<u8>>,
    loc_rec: broadcast::Receiver<Vec<u8>>,
}

impl PeerConnection {
    /// Creates a brand new circuit with Tor Relays and returns a `PeerConnection`
    /// that can be later used for chatting
    ///
    /// # Errors
    /// TODO: This function still needs some additional changes
    pub async fn create() -> Result<Self, Box<dyn Error>> {
        let mut tor_config_builder = TorClientConfig::builder();
        let mut config_path = env::var("HOME")?;
        config_path.push_str(ARTI_KEYSTORE);
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
        let (service, request_stream) = match tor_client.launch_onion_service(svc_config)? {
            Some(s) => s,
            None => return Err("Could not launch onion service...".into()),
        };
        let hsid: tor_hsservice::HsId = match service.onion_address() {
            Some(s) => s,
            None => return Err("No HsId found.".into()),
        };
        println!("Server Address: {}", hsid.display_unredacted());
        let (rem_sen, rem_rec) = tokio::sync::broadcast::channel::<Vec<u8>>(100);
        let (loc_sen, loc_rec) = tokio::sync::broadcast::channel::<Vec<u8>>(100);

        // adding actual path for config file
        config_path.push_str(ARTI_PRIVATE_KEY);

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
            tor_client: Some(tor_client),
        })
    }

    /// Used to listen to incoming messages from peer and append it to `msg_rx`
    /// # Errors
    pub async fn init_server(&mut self) -> Result<(), Box<dyn Error>> {
        debug!("Initializing Server.");
        let mut stream = self.stream.take().ok_or("No stream assigned yet.")?;
        // accept connections and
        let rem_sx_clone = self.rem_sen.clone();
        let loc_rx_clone = self.loc_rec.resubscribe();
        let ssk_arc = Arc::clone(&self.shared_secret_key);

        // spawn a thread for handling connections from network
        tokio::spawn(async move {
            loop {
                while let Some(rendreq) = stream.next().await {
                    let mut stream = rendreq.accept().await.unwrap();
                    while let Some(strreq) = stream.next().await {
                        let stream = strreq.accept(Connected::new_empty()).await.unwrap();
                        let (reader, writer) = tokio::io::split(stream);
                        let ssk = Arc::clone(&ssk_arc);
                        let rem_sx_clone = rem_sx_clone.clone();
                        let loc_rx_clone = loc_rx_clone.resubscribe();
                        tokio::spawn(async move {
                            handle_stream(reader, writer, ssk, rem_sx_clone, loc_rx_clone)
                                .await
                                .unwrap();
                        });
                    }
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
        self.tor_client.as_ref().unwrap().connect(tuple).await?;
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
        self.connect_with_addr(peer_addr).await?;
        println!("Connected. Verifying integrity.");
        let msg = self.recv_raw().await?;

        let (de_msg, _) = bincode::serde::decode_from_slice::<Msg, _>(&msg, config::standard())?;
        let local_private_key = EphemeralSecret::random_from_rng(OsRng);
        let mut remote_public_key = None;
        println!("Performing X25519 Handshake.");
        self.x25519_handshake(&mut remote_public_key, de_msg)?;

        let local_public_key = PublicKey::from(&local_private_key);
        let msg = Msg::PublicKey(*local_public_key.as_bytes());
        let msg_bytes = bincode::serde::encode_to_vec(msg, config::standard())?;
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
        let msg = bincode::serde::encode_to_vec(msg, config::standard())?;
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
    ///
    pub async fn recv(&mut self) -> Result<Option<Msg>, Box<dyn Error>> {
        let encr_msg = match self.recv_raw().await {
            Ok(s) => s,
            Err(e) => return Ok(None),
        };
        let ssk = self.shared_secret_key.read().unwrap().to_owned();
        let msg = decrypt(&ssk, &encr_msg)?;
        let (decoded, _) = bincode::serde::decode_from_slice(&msg, config::standard())?;
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
}

/// # Errors
/// # Panics
pub async fn handle_stream<T, S>(
    reader: T,
    writer: S,
    ssk: Arc<RwLock<[u8; 32]>>,
    rem_sx: broadcast::Sender<Vec<u8>>,
    loc_rx: broadcast::Receiver<Vec<u8>>,
) -> Result<(), Box<dyn Error>>
where
    T: AsyncReadExt + Unpin + Send + 'static,
    S: AsyncWriteExt + Unpin + Send + 'static,
{
    let mut reader = reader;
    let mut writer = writer;
    connect_as_listener(&mut reader, &mut writer, ssk).await?;
    debug!("Secret key set.");

    let rem_sx = rem_sx.clone();
    // We spawn a tokio thread to listen for incoming messages from peer
    // we convert it to clear message and push it to remote_msg_sx
    tokio::spawn(async move {
        let mut final_buf = vec![];
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => {
                    if final_buf.is_empty() {
                        break;
                    }
                    _ = rem_sx.send(final_buf.clone());
                    final_buf.clear();
                }
                Ok(size) => {
                    final_buf.extend_from_slice(&buf[..size]);
                }
                Err(e) => {
                    eprintln!("Error found: {e}");
                    break;
                }
            }
        }
    });
    let mut loc_rx = loc_rx.resubscribe();

    // We spawn this tread to listen for messages that the user sends to peer
    // convert it excrypted message, and send it over the writer
    tokio::spawn(async move {
        while let Ok(cmd) = loc_rx.recv().await {
            let encoded = bincode::serde::encode_to_vec(cmd, config::standard()).unwrap();
            _ = writer.write_all(&encoded).await;
        }
    });
    Ok(())
}
/// Used to connect to dialer
///
/// # Errors
/// # Panics
pub async fn connect_as_listener<T, S>(
    reader: &mut T,
    writer: &mut S,
    ssk: Arc<RwLock<[u8; 32]>>,
) -> Result<(), Box<dyn Error>>
where
    T: AsyncReadExt + Unpin,
    S: AsyncWriteExt + Unpin,
{
    let local_private_key = EphemeralSecret::random_from_rng(OsRng);
    let local_public_key = PublicKey::from(&local_private_key);
    let signing_key = signing_key()?;
    let signature = signing_key.sign(local_public_key.as_bytes());
    let msg = Msg::SignedAndPublicKey(signature.to_vec(), *local_public_key.as_bytes());
    let shared_and_signed_key = bincode::serde::encode_to_vec(msg, config::standard())?;
    debug!("Sending Signature & Public Key to peer.");
    writer.write_all(&shared_and_signed_key).await?;
    let mut vec = Vec::new();
    let mut buf = [0u8; 1024];
    debug!("Reading peer's public key.");
    while reader.read(&mut buf).await? != 0 {
        vec.extend_from_slice(&buf);
    }
    debug!("Parsing peer's public key.");
    let (recv_msg, _) = bincode::serde::decode_from_slice::<Msg, _>(&vec, config::standard())?;

    if let Msg::PublicKey(remote_public_key) = recv_msg {
        let rpk = PublicKey::from(remote_public_key);
        let shared_secret_key = local_private_key.diffie_hellman(&rpk);
        *ssk.write().unwrap() = *shared_secret_key.as_bytes();
    }
    Ok(())
}
