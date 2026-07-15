use core::panic;
use std::str::FromStr;

use bincode::config;
use ed25519_dalek::ed25519::signature::rand_core::OsRng;
use safelog::DisplayRedacted;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tor_hsservice::HsId;
use tor_llcrypto::pk::ed25519::Ed25519PublicKey;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::{
    config::parse_config,
    msg::Msg,
    operations::{decrypt, dialer_actor, edhverify, encrypt, signing_key, x25519_handshake},
};

#[test]
/// Tests excryption and decryption algorithms
fn test_cryptography() {
    let msg = Msg::Text("This is a test text".to_string());
    let p1_private_key = EphemeralSecret::random_from_rng(OsRng);
    let p2_private_key = EphemeralSecret::random_from_rng(OsRng);
    let p2_public_key = PublicKey::from(&p2_private_key);
    let shared_secret_key = p1_private_key.diffie_hellman(&p2_public_key);
    let serialized_msg = bincode::serde::encode_to_vec(&msg, config::standard()).unwrap();
    let encrypted_text = encrypt(shared_secret_key.as_bytes(), &serialized_msg).unwrap();
    let decrypted_text = decrypt(shared_secret_key.as_bytes(), &encrypted_text).unwrap();
    let (deserialized, _) =
        bincode::serde::decode_from_slice(&decrypted_text, config::standard()).unwrap();
    assert_eq!(msg, deserialized);
}

// #[tokio::test]
// async fn test_verification() {
//     // assuming p1 as local peer and a listener
//     // p2 as remote dialer
//     // this is the link that got generated on my end, and WILL be different on yours.
//     // change it when testing
//     let p1_hsid = "sg6ifrxlrrjbvslgfdodqxs27zfngheayftxhdenblpmerjcclr4raad.onion";
//     let key_path = parse_config().unwrap().arti_key_store;
//     let signing_key = signing_key(key_path).await.unwrap();
//     let (mut p1_sock, mut p2_sock) = tokio::io::duplex(100);
//
//     tokio::spawn(async move {
//         let (mut reader, mut writer) = tokio::io::split(p1_sock);
//         let mut ssk = None;
//         dialer_actor(
//             key_path,
//             &mut reader,
//             &mut writer,
//             &mut ssk,
//             local_hsid,
//             peer_addr,
//         )
//         .await;
//     });
//     tokio::spawn(async move {
//         let (mut reader, mut writer) = tokio::io::split(p2_sock);
//     });
// }
