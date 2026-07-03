use bincode::config;
use serde::{Deserialize, Serialize};

pub enum PeerVerified {
    Verified,
    Invalid,
}

#[derive(Default)]
pub enum PeerStatus {
    Connected,
    #[default]
    NotFound,
}

#[derive(Clone)]
pub enum Internal {
    SecretKey([u8; 32]),
    RemoteSender(Vec<u8>),
    RemoteRecv(Vec<u8>),
    LocalSender(Vec<u8>),
    LocalRecv(Vec<u8>),
}

#[non_exhaustive]
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum Msg {
    Text(String),
    PublicKey([u8; 32]),
    SignedAndPublicKey(Vec<u8>, [u8; 32]),
    Begin,
    End,
}

impl Msg {
    /// # Panics
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        bincode::serde::encode_to_vec(self, config::legacy()).unwrap()
    }

    /// # Panics
    #[must_use]
    pub fn from_bytes(&self, bytes: &[u8]) -> Self {
        let (msg, _) =
            bincode::serde::decode_from_slice::<Msg, _>(bytes, config::legacy()).unwrap();
        msg
    }
}

impl From<&str> for Msg {
    fn from(value: &str) -> Self {
        Msg::Text(value.to_string())
    }
}
