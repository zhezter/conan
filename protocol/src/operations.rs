use crate::{
    constants::{ARTI_PRIVATE_KEY, ENCRYPTION_INFO},
    msg::Msg,
};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Generate},
};
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use std::{error::Error, fs::File, io::Read, str::FromStr};
use tokio::io::{AsyncWriteExt, WriteHalf};
use tor_hsservice::HsId;
use x25519_dalek::{EphemeralSecret, PublicKey};

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
pub fn signing_key(arti_key_store: String) -> Result<SigningKey, Box<dyn Error>> {
    let mut key_store_path = arti_key_store;
    key_store_path.push_str(ARTI_PRIVATE_KEY);
    let mut signing_file = File::open(key_store_path)?;
    let mut buf = [0u8; 32];
    signing_file.read_exact(&mut buf)?;
    let key = SigningKey::from_bytes(&buf);
    Ok(key)
}

pub fn x25519_handshake(
    remote_public_key: &mut Option<PublicKey>,
    peer_addr: &(String, u16),
    msg: Msg,
) -> Result<(), Box<dyn Error>> {
    let Msg::SignedAndPublicKey(signature, claimed_remote_public_key) = msg else {
        return Err("No Signed Public key found.".into());
    };
    let hsid = HsId::from_str(&peer_addr.0)?;
    let hsid_bytes = hsid.as_ref();
    let verifying_key = VerifyingKey::from_bytes(hsid_bytes)?;
    let signature: [u8; 64] = match signature.try_into() {
        Ok(s) => s,
        Err(e) => {
            return Err(format!("Cannot convert signature to Array, len {}", e.len()).into());
        }
    };
    let signature = Signature::from_bytes(&signature);
    verifying_key.verify(&claimed_remote_public_key, &signature)?;
    *remote_public_key = Some(PublicKey::from(claimed_remote_public_key));
    Ok(())
}

pub async fn edhverify<T>(
    writer: &mut WriteHalf<T>,
    local_private_key: EphemeralSecret,
    remote_public_key: PublicKey,
    ssk: &mut Option<[u8; 32]>,
) -> Result<(), Box<dyn Error>>
where
    T: AsyncWriteExt,
{
    let local_public_key = PublicKey::from(&local_private_key);
    let shared_secret_key = local_private_key.diffie_hellman(&remote_public_key);
    let msg_bytes = Msg::PublicKey(*local_public_key.as_bytes()).to_vec();
    writer.write_u16(msg_bytes.len() as u16).await?;
    writer.write_all(&msg_bytes).await?;
    writer.flush().await?;
    *ssk = Some(*shared_secret_key.as_bytes());

    Ok(())
}
