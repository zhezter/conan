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
    msg::Msg,
    operations::{decrypt, edhverify, encrypt, signing_key, x25519_handshake},
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

#[tokio::test]
async fn test_verification() {
    // assuming p1 as local peer and a listener
    // p2 as remote dialer
    // this is the link that got generated on my end, and WILL be different on yours.
    // change it when testing
    let p1_hsid = "sg6ifrxlrrjbvslgfdodqxs27zfngheayftxhdenblpmerjcclr4raad.onion";
    let key_path = "/home/grishma/.conan/user1";
    let (mut p1_sock, mut p2_sock) = tokio::io::duplex(100);
    let p1_signing_key = signing_key(key_path.into()).unwrap();
    // self note: Verifying key is always the Public Key.
    let p1_verifying_key = p1_signing_key.public_key();

    let p1_private_key = EphemeralSecret::random_from_rng(OsRng);
    let p1_public_key = PublicKey::from(&p1_private_key);

    // verifying that verifying key actually matches signing key's verifying key.
    let hsid = HsId::from_str(p1_hsid).unwrap();
    let hsid_bytes = hsid.as_ref();
    assert_eq!(hsid_bytes, p1_verifying_key.as_bytes());

    // p1 preparing message to be sent to p2
    let signature = p1_signing_key.sign(p1_public_key.as_bytes());
    let signed_public_key_bytes =
        Msg::SignedAndPublicKey(signature.to_bytes().to_vec(), p1_public_key.to_bytes()).to_vec();

    // p1 writes data to p2
    #[allow(clippy::cast_possible_truncation)]
    p1_sock
        .write_u16(signed_public_key_bytes.len() as u16)
        .await
        .unwrap();
    p1_sock.flush().await.unwrap();
    p1_sock.write_all(&signed_public_key_bytes).await.unwrap();
    p1_sock.flush().await.unwrap();

    // p2 reads data
    let buf_len = p2_sock.read_u16().await.unwrap() as usize;
    let mut buf = vec![0u8; buf_len];
    let size = p2_sock.read_exact(&mut buf).await.unwrap();
    let msg = Msg::from_bytes(&buf[..size]);
    let p2_private_key = EphemeralSecret::random_from_rng(OsRng);
    let p2_public_key = PublicKey::from(&p2_private_key);
    // confirms message received is this enum exactly
    let mut remote_public_key = None;
    if let Err(e) = x25519_handshake(&mut remote_public_key, &(p1_hsid.to_string(), 80), msg) {
        panic!("X25519 Verification Error: {e}");
    }

    let msg_reply = Msg::PublicKey(p2_public_key.to_bytes()).to_vec();
    #[allow(clippy::cast_possible_truncation)]
    p2_sock.write_u16(msg_reply.len() as u16).await.unwrap();
    p2_sock.write_all(&msg_reply).await.unwrap();
    p2_sock.flush().await.unwrap();
    // if we reach here, we know listener is verified, go to stage 2
    let mut shared_secret_key = None;
    let (_, mut w) = tokio::io::split(p2_sock);
    if let Err(e) = edhverify(
        &mut w,
        p2_private_key,
        remote_public_key.unwrap(),
        &mut shared_secret_key,
    )
    .await
    {
        panic!("EDH Verification Error: {e}");
    }
}
