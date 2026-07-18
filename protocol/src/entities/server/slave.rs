use arti_client::DataStream;
use conan_crypto::ratchet::RatchetSession;
use rand::random_range;
use rusqlite::Connection;
use std::{error::Error, sync::Arc};
use tokio::{
    io::{ReadHalf, WriteHalf},
    sync::{RwLock, broadcast},
};
use tor_hsservice::RunningOnionService;

use crate::{
    comm::enums::IPCRes,
    config::ConanConfig,
    entities::database::peer::{Peer, PeerData},
    extras::generate_name,
    msg::{Internal, Msg},
    operations::{listener_actor, recv},
};

pub struct Slave {
    pub id: u8,
    pub reader: Option<ReadHalf<DataStream>>,
    pub writer: WriteHalf<DataStream>,
    pub response_sender: broadcast::Sender<(u8, Internal)>,
    /// Double Ratchet session for encrypted communication.
    /// `None` before handshake completes, `Some` after.
    pub ratchet_session: Option<Arc<RwLock<RatchetSession>>>,
    pub msg_sender: broadcast::Sender<IPCRes>,
    pub service: Arc<RunningOnionService>,
    pub config: ConanConfig,
}

impl Slave {
    /// Spawns a tokio thread that reads encrypted messages and forwards to response channel.
    ///
    /// # Errors
    /// # Panics
    pub fn spawn_communication(&mut self) -> Result<(), Box<dyn Error>> {
        let Some(mut reader) = self.reader.take() else {
            return Err("No Reader Associated with Slave.".into());
        };
        let ratchet = self
            .ratchet_session
            .as_ref()
            .ok_or("Ratchet session not initialized")?
            .clone();
        let response_sender = self.response_sender.clone();
        let id = self.id;
        tokio::spawn(async move {
            let mut threshold = 5;
            while threshold != 0 {
                match recv(&mut reader, Arc::clone(&ratchet)).await {
                    Ok(data) => {
                        let msg = Msg::from_bytes(&data);
                        let msg = (id, Internal::Msg(msg));
                        _ = response_sender.send(msg.clone());
                        threshold = 5;
                        continue;
                    }
                    Err(e) => {
                        eprintln!("Error writing to socket.\n{e}");
                        threshold -= 1;
                    }
                }
                if threshold != 0 {
                    eprintln!("Retrying read...");
                } else {
                    response_sender
                        .send((id, Internal::RemovePeer(id)))
                        .unwrap();
                }
            }
        });
        Ok(())
    }

    /// Connects to Peer as listener (Allowing Connections)
    /// # Panics
    /// # Errors
    pub async fn connect_as_listener(&mut self) -> Result<u8, Box<dyn Error>> {
        let Some(reader) = self.reader.as_mut() else {
            return Err("No reader found.".into());
        };
        let local_hsid = self
            .service
            .onion_address()
            .ok_or("Could not get Onion Address")?;
        let mut remote_onion_key = None;
        let (session, _remote_hsid) = listener_actor(
            self.config.arti_key_store.clone(),
            reader,
            &mut self.writer,
            &mut remote_onion_key,
            local_hsid,
        )
        .await?;
        self.ratchet_session = Some(Arc::new(RwLock::new(session)));
        let Some(remote_hsid) = remote_onion_key else {
            return Err("No Remote HsId key assigned. Aborting.".into());
        };
        let dbconn = Connection::open(&self.config.db_path)?;
        let peer = if let Some(peer) = dbconn.get_peer_from_addr(&remote_hsid)? {
            peer
        } else {
            let name = generate_name(random_range(4..10));
            dbconn.insert_peer(Peer::build(&name, &remote_hsid))?
        };
        let name = peer.name;
        #[allow(clippy::cast_possible_truncation)]
        let id = peer.id as u8;
        self.id = id;
        self.msg_sender.send(IPCRes::Notification(format!(
            "{name} just connected to you."
        )))?;
        Ok(id)
    }
}
