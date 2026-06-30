pub mod keys;
pub mod lco;
pub mod parallel;
use parallel::{parallel_decrypt_payload, parallel_encrypt_payload};

use keys::{HybridPrivateKey, HybridPublicKey};
use ml_kem::{Decapsulate, Encapsulate};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use log::{debug, info};
use lvau_protocol::envelope::{
    AlgorithmId, Envelope, EnvelopeHeader, KdfParams, Recipient, SecurityProfile, CURRENT_VERSION,
    MAGIC_REAL,
};
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, Secret};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::Path;
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] postcard::Error),
    #[error("Envelope validation failed: {0}")]
    Validation(&'static str),
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed (tampered data or wrong key)")]
    DecryptionFailed,
    #[error("Unsupported security profile")]
    UnsupportedProfile,
    #[error("Missing KDF parameters")]
    MissingKdfParams,
    #[error("Missing secondary nonce for cascade")]
    MissingSecondaryNonce,
}

fn derive_master_key(
    password: &Secret<String>,
    seed: Option<&Secret<String>>,
    kdf: &KdfParams,
) -> Zeroizing<[u8; 32]> {
    match kdf {
        KdfParams::Argon2id {
            m_cost,
            t_cost,
            p_cost,
            salt,
        } => {
            info!(
                "Initializing Argon2id KDF with m_cost={}, t_cost={}, p_cost={}",
                m_cost, t_cost, p_cost
            );
            let params = Params::new(*m_cost, *t_cost, *p_cost, Some(32)).unwrap();

            let argon2 = if let Some(s) = seed {
                debug!("Applying cryptographic seed (pepper) to KDF.");
                Argon2::new_with_secret(
                    s.expose_secret().as_bytes(),
                    Algorithm::Argon2id,
                    Version::V0x13,
                    params,
                )
                .unwrap()
            } else {
                Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            };

            let mut master_key = Zeroizing::new([0u8; 32]);
            info!("Deriving master key from password...");
            argon2
                .hash_password_into(password.expose_secret().as_bytes(), salt, &mut *master_key)
                .unwrap();

            master_key
        }
    }
}

pub fn encrypt_file_password(
    input_path: &Path,
    output_path: &Path,
    password: Secret<String>,
    seed: Option<Secret<String>>,
    profile: SecurityProfile,
) -> Result<(), CryptoError> {
    info!("Starting encryption of {}", input_path.display());
    let mut rng = OsRng;

    let plaintext = fs::read(input_path)?;

    let (m_cost, t_cost, p_cost) = match profile {
        SecurityProfile::Fast => (16384, 1, 1),
        SecurityProfile::Balanced => (65536, 2, 1),
        SecurityProfile::Archive => (262144, 3, 2),
        SecurityProfile::Paranoid => (1048576, 4, 4),
        SecurityProfile::Extreme => (1048576, 4, 4), // Same Argon parameters as Paranoid
    };

    let algorithm = match profile {
        SecurityProfile::Extreme => AlgorithmId::TripleCascadeAesXChaChaLco,
        SecurityProfile::Paranoid => AlgorithmId::CascadeAesGcmXChaCha,
        _ => AlgorithmId::XChaCha20Poly1305,
    };
    info!("Selected algorithm: {:?}", algorithm);

    let mut salt = [0u8; 16];
    rng.fill_bytes(&mut salt);

    let kdf = KdfParams::Argon2id {
        m_cost,
        t_cost,
        p_cost,
        salt,
    };
    let master_key = derive_master_key(&password, seed.as_ref(), &kdf);

    let mut nonce_bytes = [0u8; 24];
    rng.fill_bytes(&mut nonce_bytes);

    let mut secondary_nonce_bytes = None;
    if algorithm == AlgorithmId::CascadeAesGcmXChaCha
        || algorithm == AlgorithmId::TripleCascadeAesXChaChaLco
    {
        let mut sn = [0u8; 12];
        rng.fill_bytes(&mut sn);
        secondary_nonce_bytes = Some(sn);
    }

    let header = EnvelopeHeader {
        magic: MAGIC_REAL,
        version: CURRENT_VERSION,
        profile,
        algorithm: algorithm.clone(),
        kdf: Some(kdf),
        recipients: vec![Recipient::Password],
    };

    let header_bytes = postcard::to_allocvec(&header)?;
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(&header_bytes);
    let aad_hash: [u8; 32] = hasher.finalize().into();

    let hk = Hkdf::<Sha256>::new(None, &*master_key);

    let ciphertext = parallel_encrypt_payload(
        &algorithm,
        &plaintext,
        &hk,
        &nonce_bytes,
        secondary_nonce_bytes,
        &aad_hash,
    )?;

    let envelope = Envelope {
        header,
        nonce: nonce_bytes,
        secondary_nonce: secondary_nonce_bytes,
        aad_hash,
        ciphertext,
        metadata: Vec::new(),
    };

    info!("Writing encrypted envelope to {}", output_path.display());
    let encoded_envelope = postcard::to_allocvec(&envelope)?;
    fs::write(output_path, encoded_envelope)?;

    Ok(())
}

pub fn encrypt_file_keypair(
    in_path: &Path,
    out_path: &Path,
    recipient_pub: &HybridPublicKey,
    profile: SecurityProfile,
) -> Result<(), CryptoError> {
    info!(
        "Starting hybrid keypair encryption for {}",
        in_path.display()
    );

    let plaintext = fs::read(in_path)?;
    let mut rng = OsRng;

    // Determine algorithm logic (same as password path)
    let algorithm = match profile {
        SecurityProfile::Extreme => AlgorithmId::TripleCascadeAesXChaChaLco,
        SecurityProfile::Paranoid => AlgorithmId::CascadeAesGcmXChaCha,
        _ => AlgorithmId::XChaCha20Poly1305,
    };

    let mut nonce_bytes = [0u8; 24];
    rng.fill_bytes(&mut nonce_bytes);

    let mut secondary_nonce_bytes = None;
    if algorithm == AlgorithmId::CascadeAesGcmXChaCha
        || algorithm == AlgorithmId::TripleCascadeAesXChaChaLco
    {
        let mut sn = [0u8; 12];
        rng.fill_bytes(&mut sn);
        secondary_nonce_bytes = Some(sn);
    }

    // 1. Generate ephemeral X25519
    let ephem_x25519_priv = StaticSecret::random_from_rng(rng);
    let ephem_x25519_pub = X25519PublicKey::from(&ephem_x25519_priv);
    let x25519_ss = ephem_x25519_priv.diffie_hellman(&recipient_pub.x25519);

    // 2. Encapsulate with ML-KEM
    let (mlkem_ct, mlkem_ss) = recipient_pub.mlkem.encapsulate();

    // 3. Combine shared secrets via HKDF to derive file key
    let mut combined_ss = Vec::new();
    combined_ss.extend_from_slice(x25519_ss.as_bytes());
    combined_ss.extend_from_slice(mlkem_ss.as_slice());

    let hk = Hkdf::<Sha256>::new(None, &combined_ss);
    let mut payload_key = Zeroizing::new([0u8; 32]);
    let _ = hk.expand(b"Lvau-Hybrid-Payload", &mut *payload_key);

    let header = EnvelopeHeader {
        magic: MAGIC_REAL,
        version: CURRENT_VERSION,
        profile: profile.clone(),
        algorithm: algorithm.clone(),
        kdf: None, // No KDF used
        recipients: vec![Recipient::X25519MlkemHybrid {
            ephemeral_public_x25519: ephem_x25519_pub.to_bytes(),
            mlkem_ciphertext: mlkem_ct.as_slice().to_vec(),
            encrypted_file_key: vec![], // In this simplified version, the derived key IS the payload key.
        }],
    };

    // Serializing header and aad computation is same
    let aad = postcard::to_allocvec(&header)?;
    let mut hasher = Sha256::new();
    hasher.update(&aad);
    let aad_hash: [u8; 32] = hasher.finalize().into();

    let ciphertext = parallel_encrypt_payload(
        &algorithm,
        &plaintext,
        &hk,
        &nonce_bytes,
        secondary_nonce_bytes,
        &aad_hash,
    )?;

    let envelope = Envelope {
        header,
        nonce: nonce_bytes,
        secondary_nonce: secondary_nonce_bytes,
        aad_hash,
        ciphertext,
        metadata: vec![],
    };

    let encoded = postcard::to_allocvec(&envelope)?;
    let mut file = fs::File::create(out_path)?;
    file.write_all(&encoded)?;
    Ok(())
}

pub fn decrypt_file_keypair(
    in_path: &Path,
    out_path: &Path,
    priv_key: &HybridPrivateKey,
) -> Result<(), CryptoError> {
    let data = fs::read(in_path)?;
    let plaintext = decrypt_memory_keypair(&data, priv_key)?;
    fs::write(out_path, plaintext)?;
    Ok(())
}

pub fn decrypt_memory_keypair(
    data: &[u8],
    priv_key: &HybridPrivateKey,
) -> Result<Vec<u8>, CryptoError> {
    let envelope: Envelope = postcard::from_bytes(data)?;
    envelope
        .validate()
        .map_err(|_| CryptoError::Validation("Invalid magic bytes or missing MAC"))?;

    let recipient = envelope
        .header
        .recipients
        .iter()
        .find(|r| matches!(r, Recipient::X25519MlkemHybrid { .. }))
        .ok_or(CryptoError::DecryptionFailed)?;

    let payload_key = if let Recipient::X25519MlkemHybrid {
        ephemeral_public_x25519,
        mlkem_ciphertext,
        ..
    } = recipient
    {
        let ephem_pub = X25519PublicKey::from(*ephemeral_public_x25519);
        let x25519_ss = priv_key.x25519.diffie_hellman(&ephem_pub);

        let mlkem_ct = mlkem_ciphertext
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::DecryptionFailed)?;
        let mlkem_ss = priv_key.mlkem.decapsulate(&mlkem_ct);

        let mut combined_ss = Vec::new();
        combined_ss.extend_from_slice(x25519_ss.as_bytes());
        combined_ss.extend_from_slice(mlkem_ss.as_slice());

        let hk = Hkdf::<Sha256>::new(None, &combined_ss);
        let mut pk = Zeroizing::new([0u8; 32]);
        hk.expand(b"Lvau-Hybrid-Payload", &mut *pk).unwrap();
        pk
    } else {
        return Err(CryptoError::DecryptionFailed);
    };

    let mut hasher = Sha256::new();
    let aad = postcard::to_allocvec(&envelope.header)?;
    hasher.update(&aad);
    let computed_hash: [u8; 32] = hasher.finalize().into();

    if computed_hash != envelope.aad_hash {
        return Err(CryptoError::Validation(
            "Invalid metadata in decrypted payload",
        ));
    }

    let plaintext = parallel_decrypt_payload(
        &envelope.header.algorithm,
        &envelope.ciphertext,
        &Hkdf::<Sha256>::from_prk(payload_key.as_ref())
            .map_err(|_| CryptoError::DecryptionFailed)?,
        &envelope.nonce,
        envelope.secondary_nonce,
        &envelope.aad_hash,
    )?;

    Ok(plaintext)
}

pub fn decrypt_memory_password(
    encoded_envelope: &[u8],
    password: Secret<String>,
    seed: Option<Secret<String>>,
) -> Result<Vec<u8>, CryptoError> {
    info!("Parsing Lvau Envelope from memory...");
    let envelope: Envelope = postcard::from_bytes(encoded_envelope)?;

    envelope.validate().map_err(CryptoError::Validation)?;

    let kdf = envelope
        .header
        .kdf
        .as_ref()
        .ok_or(CryptoError::MissingKdfParams)?;
    let master_key = derive_master_key(&password, seed.as_ref(), kdf);
    let hk = Hkdf::<Sha256>::new(None, &*master_key);

    let plaintext = parallel_decrypt_payload(
        &envelope.header.algorithm,
        &envelope.ciphertext,
        &hk,
        &envelope.nonce,
        envelope.secondary_nonce,
        &envelope.aad_hash,
    )?;

    info!("Decryption successful.");
    Ok(plaintext)
}

pub fn decrypt_file_password(
    input_path: &Path,
    output_path: &Path,
    password: Secret<String>,
    seed: Option<Secret<String>>,
) -> Result<(), CryptoError> {
    info!("Starting decryption of {}", input_path.display());
    let encoded_envelope = fs::read(input_path)?;
    let plaintext = decrypt_memory_password(&encoded_envelope, password, seed)?;
    info!("Writing decrypted file to {}", output_path.display());
    fs::write(output_path, plaintext)?;
    Ok(())
}

pub fn inspect_envelope(input_path: &Path) -> Result<EnvelopeHeader, CryptoError> {
    let encoded_envelope = fs::read(input_path)?;
    let envelope: Envelope = postcard::from_bytes(&encoded_envelope)?;
    envelope.validate().map_err(CryptoError::Validation)?;
    Ok(envelope.header)
}

#[cfg(test)]
mod tests;
