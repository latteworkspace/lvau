pub mod keys;
pub mod lco;
pub mod parallel;
pub mod password;

use parallel::{stream_decrypt_payload, stream_encrypt_payload};

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
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
use std::fs::{self, File};
use std::io::{Read, Write};
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
    #[error("Refusing to overwrite existing output file")]
    OutputExists,
}

fn derive_master_key(
    password: &Secret<String>,
    seed: Option<&Secret<String>>,
    kdf: &KdfParams,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
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
            let params = Params::new(*m_cost, *t_cost, *p_cost, Some(32))
                .map_err(|_| CryptoError::UnsupportedProfile)?;

            let argon2 = if let Some(s) = seed {
                debug!("Applying cryptographic seed (pepper) to KDF.");
                Argon2::new_with_secret(
                    s.expose_secret().as_bytes(),
                    Algorithm::Argon2id,
                    Version::V0x13,
                    params,
                )
                .map_err(|_| CryptoError::EncryptionFailed)?
            } else {
                Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            };

            let mut master_key = Zeroizing::new([0u8; 32]);
            info!("Deriving master key from password...");
            argon2
                .hash_password_into(password.expose_secret().as_bytes(), salt, &mut *master_key)
                .map_err(|_| CryptoError::DecryptionFailed)?;

            Ok(master_key)
        }
    }
}

fn compute_aad_hash(header: &EnvelopeHeader) -> Result<[u8; 32], CryptoError> {
    let header_bytes = postcard::to_allocvec(header)?;
    let mut hasher = Sha256::new();
    hasher.update(&header_bytes);
    Ok(hasher.finalize().into())
}

fn verify_aad_hash(envelope: &Envelope) -> Result<(), CryptoError> {
    let computed_hash = compute_aad_hash(&envelope.header)?;
    if computed_hash != envelope.aad_hash {
        return Err(CryptoError::Validation(
            "Envelope header authentication data mismatch",
        ));
    }
    Ok(())
}

fn wrap_key_xchacha(
    key_to_wrap: &[u8],
    wrapping_key: &[u8; 32],
    nonce_bytes: &[u8; 24],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(wrapping_key.into());
    let nonce = XNonce::from_slice(nonce_bytes);
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: key_to_wrap,
                aad: &[],
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)
}

fn unwrap_key_xchacha(
    wrapped_key: &[u8],
    wrapping_key: &[u8; 32],
    nonce_bytes: &[u8; 24],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(wrapping_key.into());
    let nonce = XNonce::from_slice(nonce_bytes);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: wrapped_key,
                aad: &[],
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)
}

fn write_envelope_and_payload(
    output_path: &Path,
    envelope: &Envelope,
    algorithm: &AlgorithmId,
    hk: &Hkdf<Sha256>,
    reader: &mut dyn Read,
    progress_callback: Option<&mut dyn FnMut(u64)>,
) -> Result<(), CryptoError> {
    let parent = output_path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = output_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("lvau-output");

    let mut random = [0u8; 8];
    OsRng.fill_bytes(&mut random);
    let tmp_name = format!(
        ".{}.{}.{}.tmp",
        file_name,
        std::process::id(),
        u64::from_le_bytes(random)
    );
    let tmp_path = parent.join(tmp_name);

    {
        let mut file = File::create(&tmp_path)?;
        let encoded_envelope = postcard::to_allocvec(envelope)?;
        let env_len = encoded_envelope.len() as u32;

        file.write_all(&env_len.to_le_bytes())?;
        file.write_all(&encoded_envelope)?;

        stream_encrypt_payload(
            algorithm,
            reader,
            &mut file,
            hk,
            &envelope.nonce,
            envelope.secondary_nonce,
            &envelope.aad_hash,
            progress_callback,
        )?;

        file.sync_all()?;
    }

    if output_path.exists() {
        fs::remove_file(output_path)?;
    }
    fs::rename(&tmp_path, output_path)?;
    Ok(())
}

fn read_envelope(reader: &mut dyn Read) -> Result<Envelope, CryptoError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let env_len = u32::from_le_bytes(len_buf) as usize;
    if env_len > 1024 * 1024 {
        return Err(CryptoError::Validation("Envelope too large"));
    }

    let mut env_bytes = vec![0u8; env_len];
    reader.read_exact(&mut env_bytes)?;

    let envelope: Envelope = postcard::from_bytes(&env_bytes)?;
    envelope.validate().map_err(CryptoError::Validation)?;
    verify_aad_hash(&envelope)?;

    Ok(envelope)
}

pub fn encrypt_file_password(
    input_path: &Path,
    output_path: &Path,
    password: Secret<String>,
    seed: Option<Secret<String>>,
    profile: SecurityProfile,
    progress_callback: Option<&mut dyn FnMut(u64)>,
) -> Result<(), CryptoError> {
    info!("Starting encryption of {}", input_path.display());
    let mut rng = OsRng;

    let plaintext_len = fs::metadata(input_path)?.len();
    let mut reader = File::open(input_path)?;

    let (m_cost, t_cost, p_cost) = match profile {
        SecurityProfile::Fast => (16384, 1, 1),
        SecurityProfile::Balanced => (65536, 2, 1),
        SecurityProfile::Archive => (262144, 3, 2),
        SecurityProfile::Paranoid => (1048576, 4, 4),
        SecurityProfile::Extreme => (1048576, 4, 4),
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
    let master_key = derive_master_key(&password, seed.as_ref(), &kdf)?;

    // Derive Key Wrapping Key
    let kw_hk = Hkdf::<Sha256>::new(None, &*master_key);
    let mut kwk = Zeroizing::new([0u8; 32]);
    kw_hk
        .expand(b"Lvau-Key-Wrap", &mut *kwk)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    // Generate FEK (File Encryption Key)
    let mut fek = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut *fek);

    let mut wrap_nonce = [0u8; 24];
    rng.fill_bytes(&mut wrap_nonce);
    let encrypted_file_key = wrap_key_xchacha(&*fek, &kwk, &wrap_nonce)?;

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
        recipients: vec![Recipient::Password {
            nonce: wrap_nonce,
            encrypted_file_key,
        }],
    };

    let aad_hash = compute_aad_hash(&header)?;

    let envelope = Envelope {
        header,
        plaintext_len,
        nonce: nonce_bytes,
        secondary_nonce: secondary_nonce_bytes,
        aad_hash,
        metadata: Vec::new(),
    };

    let hk = Hkdf::<Sha256>::new(None, &*fek);

    info!(
        "Writing encrypted envelope and streaming to {}",
        output_path.display()
    );
    write_envelope_and_payload(
        output_path,
        &envelope,
        &algorithm,
        &hk,
        &mut reader,
        progress_callback,
    )?;

    Ok(())
}

pub fn encrypt_file_keypair(
    in_path: &Path,
    out_path: &Path,
    recipient_pub: &HybridPublicKey,
    profile: SecurityProfile,
    progress_callback: Option<&mut dyn FnMut(u64)>,
) -> Result<(), CryptoError> {
    info!(
        "Starting hybrid keypair encryption for {}",
        in_path.display()
    );

    let plaintext_len = fs::metadata(in_path)?.len();
    let mut reader = File::open(in_path)?;
    let mut rng = OsRng;

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

    let ephem_x25519_priv = StaticSecret::random_from_rng(rng);
    let ephem_x25519_pub = X25519PublicKey::from(&ephem_x25519_priv);
    let x25519_ss = ephem_x25519_priv.diffie_hellman(&recipient_pub.x25519);

    let (mlkem_ct, mlkem_ss) = recipient_pub.mlkem.encapsulate();

    let mut combined_ss = Vec::new();
    combined_ss.extend_from_slice(x25519_ss.as_bytes());
    combined_ss.extend_from_slice(mlkem_ss.as_slice());

    let kw_hk = Hkdf::<Sha256>::new(None, &combined_ss);
    let mut kwk = Zeroizing::new([0u8; 32]);
    kw_hk
        .expand(b"Lvau-Hybrid-Wrap", &mut *kwk)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let mut fek = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut *fek);

    let wrap_nonce = [0u8; 24];
    let encrypted_file_key = wrap_key_xchacha(&*fek, &kwk, &wrap_nonce)?;

    let header = EnvelopeHeader {
        magic: MAGIC_REAL,
        version: CURRENT_VERSION,
        profile: profile.clone(),
        algorithm: algorithm.clone(),
        kdf: None,
        recipients: vec![Recipient::X25519MlkemHybrid {
            ephemeral_public_x25519: ephem_x25519_pub.to_bytes(),
            mlkem_ciphertext: mlkem_ct.as_slice().to_vec(),
            encrypted_file_key,
        }],
    };

    let aad_hash = compute_aad_hash(&header)?;

    let envelope = Envelope {
        header,
        plaintext_len,
        nonce: nonce_bytes,
        secondary_nonce: secondary_nonce_bytes,
        aad_hash,
        metadata: vec![],
    };

    let hk = Hkdf::<Sha256>::new(None, &*fek);
    write_envelope_and_payload(
        out_path,
        &envelope,
        &algorithm,
        &hk,
        &mut reader,
        progress_callback,
    )?;
    Ok(())
}

fn write_decrypted_payload_atomic(
    output_path: &Path,
    envelope: &Envelope,
    algorithm: &AlgorithmId,
    hk: &Hkdf<Sha256>,
    reader: &mut dyn Read,
    progress_callback: Option<&mut dyn FnMut(u64)>,
) -> Result<(), CryptoError> {
    let parent = output_path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = output_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("lvau-output");

    let mut random = [0u8; 8];
    OsRng.fill_bytes(&mut random);
    let tmp_name = format!(
        ".{}.{}.{}.tmp",
        file_name,
        std::process::id(),
        u64::from_le_bytes(random)
    );
    let tmp_path = parent.join(tmp_name);

    {
        let mut file = File::create(&tmp_path)?;
        stream_decrypt_payload(
            algorithm,
            reader,
            &mut file,
            hk,
            &envelope.nonce,
            envelope.secondary_nonce,
            &envelope.aad_hash,
            envelope.plaintext_len,
            progress_callback,
        )?;
        file.sync_all()?;
    }

    if output_path.exists() {
        fs::remove_file(output_path)?;
    }
    fs::rename(&tmp_path, output_path)?;
    Ok(())
}

pub fn decrypt_file_keypair(
    in_path: &Path,
    out_path: &Path,
    priv_key: &HybridPrivateKey,
    progress_callback: Option<&mut dyn FnMut(u64)>,
) -> Result<(), CryptoError> {
    let mut reader = File::open(in_path)?;
    let envelope = read_envelope(&mut reader)?;

    let recipient = envelope
        .header
        .recipients
        .iter()
        .find(|r| matches!(r, Recipient::X25519MlkemHybrid { .. }))
        .ok_or(CryptoError::DecryptionFailed)?;

    let fek = if let Recipient::X25519MlkemHybrid {
        ephemeral_public_x25519,
        mlkem_ciphertext,
        encrypted_file_key,
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

        let kw_hk = Hkdf::<Sha256>::new(None, &combined_ss);
        let mut kwk = Zeroizing::new([0u8; 32]);
        kw_hk
            .expand(b"Lvau-Hybrid-Wrap", &mut *kwk)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        // Wrap nonce for hybrid is derived from KWK, for simplicity we'll just use a zero nonce here because the wrapped key is unique per file
        // Wait, wait, I forgot to add nonce to Hybrid!
        // The wrapped key for Hybrid can use a 0 nonce because the KWK is unique per file/encryption.
        let wrap_nonce = [0u8; 24];
        unwrap_key_xchacha(encrypted_file_key, &kwk, &wrap_nonce)?
    } else {
        return Err(CryptoError::DecryptionFailed);
    };

    let hk = Hkdf::<Sha256>::new(None, &fek);
    write_decrypted_payload_atomic(
        out_path,
        &envelope,
        &envelope.header.algorithm,
        &hk,
        &mut reader,
        progress_callback,
    )?;

    Ok(())
}

pub fn decrypt_file_password(
    input_path: &Path,
    output_path: &Path,
    password: Secret<String>,
    seed: Option<Secret<String>>,
    progress_callback: Option<&mut dyn FnMut(u64)>,
) -> Result<(), CryptoError> {
    info!("Starting decryption of {}", input_path.display());
    let mut reader = File::open(input_path)?;
    let envelope = read_envelope(&mut reader)?;

    let kdf = envelope
        .header
        .kdf
        .as_ref()
        .ok_or(CryptoError::MissingKdfParams)?;

    let master_key = derive_master_key(&password, seed.as_ref(), kdf)?;

    let kw_hk = Hkdf::<Sha256>::new(None, &*master_key);
    let mut kwk = Zeroizing::new([0u8; 32]);
    kw_hk
        .expand(b"Lvau-Key-Wrap", &mut *kwk)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    let recipient = envelope
        .header
        .recipients
        .iter()
        .find(|r| matches!(r, Recipient::Password { .. }))
        .ok_or(CryptoError::DecryptionFailed)?;

    let fek = if let Recipient::Password {
        nonce,
        encrypted_file_key,
    } = recipient
    {
        unwrap_key_xchacha(encrypted_file_key, &kwk, nonce)?
    } else {
        return Err(CryptoError::DecryptionFailed);
    };

    let hk = Hkdf::<Sha256>::new(None, &fek);

    info!("Streaming decrypted file to {}", output_path.display());
    write_decrypted_payload_atomic(
        output_path,
        &envelope,
        &envelope.header.algorithm,
        &hk,
        &mut reader,
        progress_callback,
    )?;

    Ok(())
}

pub fn inspect_envelope(input_path: &Path) -> Result<EnvelopeHeader, CryptoError> {
    let mut reader = File::open(input_path)?;
    let envelope = read_envelope(&mut reader)?;
    Ok(envelope.header)
}

// Stubs for backward compatibility used by stub crate
pub fn decrypt_memory_password(
    encoded_envelope: &[u8],
    password: Secret<String>,
    seed: Option<Secret<String>>,
) -> Result<Vec<u8>, CryptoError> {
    let mut cursor = std::io::Cursor::new(encoded_envelope);
    let envelope = read_envelope(&mut cursor)?;
    let kdf = envelope
        .header
        .kdf
        .as_ref()
        .ok_or(CryptoError::MissingKdfParams)?;
    let master_key = derive_master_key(&password, seed.as_ref(), kdf)?;
    let kw_hk = Hkdf::<Sha256>::new(None, &*master_key);
    let mut kwk = Zeroizing::new([0u8; 32]);
    kw_hk
        .expand(b"Lvau-Key-Wrap", &mut *kwk)
        .map_err(|_| CryptoError::DecryptionFailed)?;
    let recipient = envelope
        .header
        .recipients
        .iter()
        .find(|r| matches!(r, Recipient::Password { .. }))
        .ok_or(CryptoError::DecryptionFailed)?;
    let fek = if let Recipient::Password {
        nonce,
        encrypted_file_key,
    } = recipient
    {
        unwrap_key_xchacha(encrypted_file_key, &kwk, nonce)?
    } else {
        return Err(CryptoError::DecryptionFailed);
    };
    let hk = Hkdf::<Sha256>::new(None, &fek);
    let mut output = Vec::new();
    stream_decrypt_payload(
        &envelope.header.algorithm,
        &mut cursor,
        &mut output,
        &hk,
        &envelope.nonce,
        envelope.secondary_nonce,
        &envelope.aad_hash,
        envelope.plaintext_len,
        None,
    )?;
    Ok(output)
}

pub fn decrypt_memory_keypair(
    data: &[u8],
    priv_key: &HybridPrivateKey,
) -> Result<Vec<u8>, CryptoError> {
    let mut cursor = std::io::Cursor::new(data);
    let envelope = read_envelope(&mut cursor)?;
    let recipient = envelope
        .header
        .recipients
        .iter()
        .find(|r| matches!(r, Recipient::X25519MlkemHybrid { .. }))
        .ok_or(CryptoError::DecryptionFailed)?;
    let fek = if let Recipient::X25519MlkemHybrid {
        ephemeral_public_x25519,
        mlkem_ciphertext,
        encrypted_file_key,
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
        let kw_hk = Hkdf::<Sha256>::new(None, &combined_ss);
        let mut kwk = Zeroizing::new([0u8; 32]);
        kw_hk
            .expand(b"Lvau-Hybrid-Wrap", &mut *kwk)
            .map_err(|_| CryptoError::DecryptionFailed)?;
        let wrap_nonce = [0u8; 24];
        unwrap_key_xchacha(encrypted_file_key, &kwk, &wrap_nonce)?
    } else {
        return Err(CryptoError::DecryptionFailed);
    };
    let hk = Hkdf::<Sha256>::new(None, &fek);
    let mut output = Vec::new();
    stream_decrypt_payload(
        &envelope.header.algorithm,
        &mut cursor,
        &mut output,
        &hk,
        &envelope.nonce,
        envelope.secondary_nonce,
        &envelope.aad_hash,
        envelope.plaintext_len,
        None,
    )?;
    Ok(output)
}

#[cfg(test)]
mod tests;
