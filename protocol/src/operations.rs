use crate::{
    config::parse_config,
    constants::{ARTI_PRIVATE_KEY, ENCRYPTION_INFO},
};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Generate},
};
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use sha2::Sha256;
use std::{error::Error, fs::File, io::Read};

/// Encrypts a `[Msg::msg]` turned to bytes to a vec of bytes
/// we assume `data` is just direct serialized version of the message without any kind of wrapper etc.
/// # Errors
#[inline]
pub fn encrypt(
    shared_secret_key: &[u8; 32],
    data: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret_key);
    let mut encryption_key = [0u8; 32];
    hk.expand(ENCRYPTION_INFO.as_bytes(), &mut encryption_key)?;

    let cipher = ChaCha20Poly1305::new_from_slice(&encryption_key)?;
    let nonce = Nonce::generate_from_rng(&mut rand::rng());
    let cipher_text = cipher.encrypt(&nonce, data)?;
    let mut new_cipher_text = nonce.to_vec();
    new_cipher_text.extend(cipher_text);
    Ok(new_cipher_text)
}

/// Decrypts a &[u8] back to message
///
/// # Errors
#[inline]
pub fn decrypt(
    shared_secret_key: &[u8; 32],
    data: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let nonce_bytes: [u8; 12] = match data[..12].try_into() {
        Ok(s) => s,
        Err(e) => return Err(format!("Cannot convert slice to nonce. {e}").into()),
    };
    let cipher_bytes = data[12..].to_vec();
    let nonce = Nonce::cast_from_core(&nonce_bytes);
    let hk = Hkdf::<Sha256>::new(None, shared_secret_key);
    let mut encryption_key = [0u8; 32];
    hk.expand(ENCRYPTION_INFO.as_bytes(), &mut encryption_key)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&encryption_key)?;
    let decrypted_bytes = cipher.decrypt(nonce, cipher_bytes.as_ref())?;

    Ok(decrypted_bytes)
}

// Commented for now. maybe removed or used later

// pub fn generate_keypair() -> Result<(), Box<dyn Error>> {
//     let signing_path = Path::new(&home_dir).join(Path::new(ARTI_KEYSTORE));
//     if !signing_path.exists() {
//         let signing_key = SigningKey::generate(&mut OsRng);
//         let mut signing_file = OpenOptions::new()
//             .create(true)
//             .truncate(true)
//             .write(true)
//             .open(signing_path)?;
//         signing_file.write_all(signing_key.as_bytes())?;
//     }
//     Ok(())
// }

/// Used to retrieve signing key for self tor server
///
/// # Errors
pub fn signing_key() -> Result<SigningKey, Box<dyn Error>> {
    let config = parse_config()?;
    let mut key_store_path = config.arti_key_store;
    key_store_path.push_str(ARTI_PRIVATE_KEY);
    let mut signing_file = File::open(key_store_path)?;
    let mut buf = [0u8; 32];
    signing_file.read_exact(&mut buf)?;
    let key = SigningKey::from_bytes(&buf);
    Ok(key)
}
