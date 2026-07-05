use arti_client::DataStream;
use bincode::config as cfg;
use ed25519_dalek::{Signer, ed25519::signature::rand_core::OsRng};
use std::{
    error::Error,
    sync::{Arc, RwLock},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    sync::broadcast,
};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::{
    comm::enums::IPCRes,
    debug,
    msg::Msg,
    operations::{decrypt, encrypt, signing_key},
};
#[derive(Debug)]
pub struct Slave {
    pub reader: ReadHalf<DataStream>,
    pub writer: WriteHalf<DataStream>,
    pub response_sender: broadcast::Sender<(u8, Msg)>,
    /// Shared secret key after diffie helmann exchange
    pub shared_secret_key: Arc<RwLock<[u8; 32]>>,
    pub msg_sender: broadcast::Sender<IPCRes>,
}

impl Slave {
    /// Consumes Self to spawn a tokio thread that forwards data from reader to response channel
    /// Forwards as is, with no decryption
    /// Decryptions and filtering is handled by `Manager` entity
    pub fn spawn_communication(self) {
        tokio::spawn(async move {
            let mut slave = self;
            loop {
                while let Ok(msg_bytes) = slave.recv().await {
                    let msg = Msg::from_bytes(&msg_bytes);
                    let msg = (0, msg);
                    _ = slave.response_sender.send(msg);
                }
            }
        });
    }

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

    /// Encrypts message before writing to writer
    pub async fn send(&mut self, msg: Vec<u8>) -> Result<(), Box<dyn Error>> {
        let ssk = self.shared_secret_key.read().unwrap();
        let encrypted = encrypt(&ssk, &msg)?;
        self.writer.write_all(&encrypted).await?;
        self.writer.flush().await?;
        Ok(())
    }

    /// Decrypts message before returning
    pub async fn recv(&mut self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut buf = [0u8; 4096];
        let size = self.reader.read(&mut buf).await?;
        let ssk = self.shared_secret_key.read().unwrap();
        let decrypted = decrypt(&ssk, &buf[..size])?;
        Ok(decrypted)
    }
}
