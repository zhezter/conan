use arti_client::DataStream;
use std::{
    error::Error,
    sync::{Arc, RwLock},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    sync::broadcast,
};
use tor_hsservice::RunningOnionService;

use crate::{
    comm::enums::IPCRes,
    msg::Msg,
    operations::{decrypt, encrypt, listener_actor},
};
pub struct Slave {
    pub reader: Option<ReadHalf<DataStream>>,
    pub writer: WriteHalf<DataStream>,
    pub response_sender: broadcast::Sender<(u8, Msg)>,
    /// Shared secret key after diffie helmann exchange
    pub shared_secret_key: Arc<RwLock<[u8; 32]>>,
    pub msg_sender: broadcast::Sender<IPCRes>,
    pub service: Arc<RunningOnionService>,
}

impl Slave {
    /// Consumes Self to spawn a tokio thread that forwards data from reader to response channel
    /// Forwards as is, with no decryption
    /// Decryptions and filtering is handled by `Manager` entity
    ///
    /// # Errors
    /// # Panics
    pub fn spawn_communication(&mut self) -> Result<(), Box<dyn Error>> {
        let Some(mut reader) = self.reader.take() else {
            return Err("No Reader Associated with Slave.".into());
        };
        let ssk = Arc::clone(&self.shared_secret_key);
        let response_sender = self.response_sender.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            for _ in 0..5 {
                match reader.read(&mut buf).await {
                    Ok(0) => {}
                    Ok(n) => {
                        let ssk = ssk.read().unwrap();
                        let Ok(decrypted) = decrypt(&ssk, &buf[..n]) else {
                            eprintln!("Found Corrupted message: {:?}", &buf[..n]);
                            continue;
                        };
                        let msg = Msg::from_bytes(&decrypted);
                        let msg = (0, msg);
                        _ = response_sender.send(msg);
                    }
                    Err(e) => {
                        eprintln!("Error writing to socket.\n{e}");
                    }
                }
                eprintln!("Retrying...");
            }
        });
        Ok(())
    }

    /// Connects to Peer as listener (Allowing Connections)
    /// # Panics
    /// # Errors
    pub async fn connect_as_listener(&mut self) -> Result<(), Box<dyn Error>> {
        let Some(reader) = self.reader.as_mut() else {
            return Err("No reader found.".into());
        };
        let local_hsid = self
            .service
            .onion_address()
            .ok_or("Could not get Onion Address")
            .unwrap();
        let mut shared_secret_key = None;
        listener_actor(reader, &mut self.writer, &mut shared_secret_key, local_hsid).await?;
        let Some(shared_secret_key) = shared_secret_key else {
            return Err("Could not parse Shared Secret Key.".into());
        };
        *self.shared_secret_key.write().unwrap() = shared_secret_key;
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
        let size = self.reader.as_mut().unwrap().read(&mut buf).await?;
        let ssk = self.shared_secret_key.read().unwrap();
        let decrypted = decrypt(&ssk, &buf[..size])?;
        Ok(decrypted)
    }
}
