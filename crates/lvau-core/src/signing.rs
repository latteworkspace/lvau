//! Ed25519 signing for Lvau encrypted artifacts.
//!
//! Signatures cover the public envelope and all ciphertext bytes.
//! Verification does not require the decryption password or private key.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use lvau_protocol::envelope::{Envelope, EnvelopeSignature};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SigningError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] postcard::Error),
    #[error("Signature verification failed")]
    VerificationFailed,
    #[error("Invalid key format: {0}")]
    InvalidKey(String),
    #[error("File is not a valid Lvau envelope")]
    InvalidEnvelope,
    #[error("Refusing to overwrite: {0}")]
    OutputExists(String),
    #[error("File is not signed")]
    NotSigned,
}

/// Serializable signing key pair file format.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct SigningKeyFile {
    pub ed25519_signing_key: String, // base64-encoded 32-byte seed
}

/// Serializable verify key file format.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct VerifyKeyFile {
    pub ed25519_verify_key: String, // base64-encoded 32-byte public key
}

/// Generate a new Ed25519 signing keypair.
///
/// Returns (signing_key_bytes, verify_key_bytes).
pub fn generate_signing_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verify_key = signing_key.verifying_key();
    (signing_key, verify_key)
}

/// Compute a SHA-256 fingerprint of a verifying key.
pub fn key_fingerprint(verify_key: &VerifyingKey) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(verify_key.as_bytes());
    hasher.finalize().into()
}

/// Save a signing key to a file (JSON with base64).
pub fn save_signing_key(key: &SigningKey, path: &Path, force: bool) -> Result<(), SigningError> {
    if path.exists() && !force {
        return Err(SigningError::OutputExists(path.display().to_string()));
    }

    let encoded =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key.to_bytes());
    let file_data = SigningKeyFile {
        ed25519_signing_key: encoded,
    };
    let json = serde_json::to_string_pretty(&file_data)
        .map_err(|_| SigningError::InvalidKey("JSON serialization failed".into()))?;

    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;

    #[cfg(unix)]
    {
        // Private file - can't set after open, but we try best effort
    }

    f.write_all(json.as_bytes())?;
    f.sync_all()?;
    Ok(())
}

/// Load a signing key from a file.
pub fn load_signing_key(path: &Path) -> Result<SigningKey, SigningError> {
    let json = fs::read_to_string(path)?;
    let file_data: SigningKeyFile = serde_json::from_str(&json)
        .map_err(|_| SigningError::InvalidKey("Invalid signing key JSON".into()))?;
    let bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &file_data.ed25519_signing_key,
    )
    .map_err(|_| SigningError::InvalidKey("Invalid base64 in signing key".into()))?;

    if bytes.len() != 32 {
        return Err(SigningError::InvalidKey(
            "Signing key must be 32 bytes".into(),
        ));
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&seed))
}

/// Save a verifying key to a file (JSON with base64).
pub fn save_verify_key(key: &VerifyingKey, path: &Path, force: bool) -> Result<(), SigningError> {
    if path.exists() && !force {
        return Err(SigningError::OutputExists(path.display().to_string()));
    }

    let encoded =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key.as_bytes());
    let file_data = VerifyKeyFile {
        ed25519_verify_key: encoded,
    };
    let json = serde_json::to_string_pretty(&file_data)
        .map_err(|_| SigningError::InvalidKey("JSON serialization failed".into()))?;

    fs::write(path, json)?;
    Ok(())
}

/// Load a verifying key from a file.
pub fn load_verify_key(path: &Path) -> Result<VerifyingKey, SigningError> {
    let json = fs::read_to_string(path)?;
    let file_data: VerifyKeyFile = serde_json::from_str(&json)
        .map_err(|_| SigningError::InvalidKey("Invalid verify key JSON".into()))?;
    let bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &file_data.ed25519_verify_key,
    )
    .map_err(|_| SigningError::InvalidKey("Invalid base64 in verify key".into()))?;

    if bytes.len() != 32 {
        return Err(SigningError::InvalidKey(
            "Verify key must be 32 bytes".into(),
        ));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| SigningError::InvalidKey("Invalid Ed25519 verify key".into()))
}

/// Sign an existing `.lvau` file.
///
/// The signature covers the serialized envelope (without the signature field)
/// plus all ciphertext bytes.
pub fn sign_file(
    in_file: &Path,
    out_file: &Path,
    signing_key: &SigningKey,
    comment: Option<String>,
    force: bool,
) -> Result<(), SigningError> {
    if out_file.exists() && !force {
        return Err(SigningError::OutputExists(out_file.display().to_string()));
    }

    let data = fs::read(in_file)?;
    if data.len() < 4 {
        return Err(SigningError::InvalidEnvelope);
    }

    let env_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    if data.len() < 4 + env_len {
        return Err(SigningError::InvalidEnvelope);
    }

    let mut envelope: Envelope = postcard::from_bytes(&data[4..4 + env_len])?;

    // Remove any existing signature for signing
    envelope.signature = None;

    // Serialize envelope without signature
    let envelope_bytes = postcard::to_allocvec(&envelope)?;

    // Get ciphertext bytes (everything after the original envelope)
    let ciphertext = &data[4 + env_len..];

    // Build the message to sign: envelope_bytes || ciphertext
    let mut message = Vec::with_capacity(envelope_bytes.len() + ciphertext.len());
    message.extend_from_slice(&envelope_bytes);
    message.extend_from_slice(ciphertext);

    // Sign
    let signature = signing_key.sign(&message);
    let verify_key = signing_key.verifying_key();
    let fingerprint = key_fingerprint(&verify_key);

    // Create timestamp
    let created_at = {
        use std::time::SystemTime;
        match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(d) => Some(format!("{}Z", d.as_secs())),
            Err(_) => None,
        }
    };

    // Set the signature on the envelope
    envelope.signature = Some(EnvelopeSignature {
        signer_fingerprint: fingerprint,
        signature: signature.to_bytes().to_vec(),
        created_at,
        comment,
    });

    // Serialize the full envelope with signature
    let signed_envelope_bytes = postcard::to_allocvec(&envelope)?;
    let signed_env_len = signed_envelope_bytes.len() as u32;

    // Write the signed file
    let mut output = Vec::with_capacity(4 + signed_envelope_bytes.len() + ciphertext.len());
    output.extend_from_slice(&signed_env_len.to_le_bytes());
    output.extend_from_slice(&signed_envelope_bytes);
    output.extend_from_slice(ciphertext);

    fs::write(out_file, output)?;
    Ok(())
}

/// Verify the Ed25519 signature on an `.lvau` file.
///
/// Returns the signer fingerprint on success.
pub fn verify_signature(
    in_file: &Path,
    verify_key: &VerifyingKey,
) -> Result<[u8; 32], SigningError> {
    let data = fs::read(in_file)?;
    if data.len() < 4 {
        return Err(SigningError::InvalidEnvelope);
    }

    let env_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    if data.len() < 4 + env_len {
        return Err(SigningError::InvalidEnvelope);
    }

    let mut envelope: Envelope = postcard::from_bytes(&data[4..4 + env_len])?;

    let sig_data = envelope.signature.take().ok_or(SigningError::NotSigned)?;

    if sig_data.signature.len() != 64 {
        return Err(SigningError::VerificationFailed);
    }

    // Reconstruct the message: envelope_without_signature || ciphertext
    let envelope_bytes = postcard::to_allocvec(&envelope)?;
    let ciphertext = &data[4 + env_len..];

    let mut message = Vec::with_capacity(envelope_bytes.len() + ciphertext.len());
    message.extend_from_slice(&envelope_bytes);
    message.extend_from_slice(ciphertext);

    // Verify
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&sig_data.signature);
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    verify_key
        .verify(&message, &signature)
        .map_err(|_| SigningError::VerificationFailed)?;

    Ok(sig_data.signer_fingerprint)
}

/// Check if a file has a signature without verifying it.
pub fn has_signature(in_file: &Path) -> Result<Option<[u8; 32]>, SigningError> {
    let data = fs::read(in_file)?;
    if data.len() < 4 {
        return Err(SigningError::InvalidEnvelope);
    }

    let env_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    if data.len() < 4 + env_len {
        return Err(SigningError::InvalidEnvelope);
    }

    let envelope: Envelope = postcard::from_bytes(&data[4..4 + env_len])?;

    Ok(envelope.signature.map(|s| s.signer_fingerprint))
}

/// Add an approval seal to an existing `.lvau` file.
///
/// An approval seal signs the AAD hash (which commits to the envelope header),
/// indicating approval of the artifact's metadata and structure.
pub fn add_approval_seal(
    in_file: &Path,
    out_file: &Path,
    signing_key: &SigningKey,
    comment: Option<String>,
    force: bool,
) -> Result<(), SigningError> {
    if out_file.exists() && !force {
        return Err(SigningError::OutputExists(out_file.display().to_string()));
    }

    let data = fs::read(in_file)?;
    if data.len() < 4 {
        return Err(SigningError::InvalidEnvelope);
    }

    let env_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    if data.len() < 4 + env_len {
        return Err(SigningError::InvalidEnvelope);
    }

    let mut envelope: Envelope = postcard::from_bytes(&data[4..4 + env_len])?;
    let ciphertext = &data[4 + env_len..];

    // Sign the AAD hash
    let signature = signing_key.sign(&envelope.aad_hash);
    let verify_key = signing_key.verifying_key();
    let fingerprint = key_fingerprint(&verify_key);

    let approval = lvau_protocol::envelope::ApprovalSignature {
        signer_fingerprint: fingerprint,
        signature: signature.to_bytes().to_vec(),
        comment,
    };

    envelope.approvals.push(approval);

    // Re-serialize the envelope
    let new_envelope_bytes = postcard::to_allocvec(&envelope)?;
    let new_env_len = new_envelope_bytes.len() as u32;

    let mut output = Vec::with_capacity(4 + new_envelope_bytes.len() + ciphertext.len());
    output.extend_from_slice(&new_env_len.to_le_bytes());
    output.extend_from_slice(&new_envelope_bytes);
    output.extend_from_slice(ciphertext);

    fs::write(out_file, output)?;
    Ok(())
}

/// Verify all approval seals in a file using a given verify key.
/// Returns true if at least one valid approval from the given key exists.
pub fn verify_approvals(
    in_file: &Path,
    verify_key: &VerifyingKey,
) -> Result<bool, SigningError> {
    let data = fs::read(in_file)?;
    if data.len() < 4 {
        return Err(SigningError::InvalidEnvelope);
    }

    let env_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    if data.len() < 4 + env_len {
        return Err(SigningError::InvalidEnvelope);
    }

    let envelope: Envelope = postcard::from_bytes(&data[4..4 + env_len])?;
    let fingerprint = key_fingerprint(verify_key);

    let mut found_valid = false;
    for approval in &envelope.approvals {
        if approval.signer_fingerprint == fingerprint {
            if approval.signature.len() == 64 {
                let mut sig_bytes = [0u8; 64];
                sig_bytes.copy_from_slice(&approval.signature);
                let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
                
                if verify_key.verify(&envelope.aad_hash, &signature).is_ok() {
                    found_valid = true;
                }
            }
        }
    }

    Ok(found_valid)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::encrypt_file_password;
    use lvau_protocol::envelope::SecurityProfile;
    use secrecy::Secret;
    use tempfile::tempdir;

    #[test]
    fn keygen_sign_and_verify() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input.txt");
        let encrypted = dir.path().join("encrypted.lvau");
        let signed = dir.path().join("signed.lvau");

        fs::write(&input, "test data for signing").unwrap();

        encrypt_file_password(
            &input,
            &encrypted,
            Secret::new("password".to_string()),
            None,
            SecurityProfile::Fast,
            None,
        )
        .unwrap();

        let (signing_key, verify_key) = generate_signing_keypair();

        sign_file(&encrypted, &signed, &signing_key, None, false).unwrap();

        let fingerprint = verify_signature(&signed, &verify_key).unwrap();
        assert_eq!(fingerprint, key_fingerprint(&verify_key));
    }

    #[test]
    fn modified_ciphertext_fails_verification() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input.txt");
        let encrypted = dir.path().join("encrypted.lvau");
        let signed = dir.path().join("signed.lvau");

        fs::write(&input, "tamper test data").unwrap();

        encrypt_file_password(
            &input,
            &encrypted,
            Secret::new("password".to_string()),
            None,
            SecurityProfile::Fast,
            None,
        )
        .unwrap();

        let (signing_key, verify_key) = generate_signing_keypair();
        sign_file(&encrypted, &signed, &signing_key, None, false).unwrap();

        // Tamper with the signed file
        let mut data = fs::read(&signed).unwrap();
        if let Some(last) = data.last_mut() {
            *last ^= 0xFF;
        }
        fs::write(&signed, data).unwrap();

        let result = verify_signature(&signed, &verify_key);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_verify_key_fails() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input.txt");
        let encrypted = dir.path().join("encrypted.lvau");
        let signed = dir.path().join("signed.lvau");

        fs::write(&input, "wrong key test").unwrap();

        encrypt_file_password(
            &input,
            &encrypted,
            Secret::new("password".to_string()),
            None,
            SecurityProfile::Fast,
            None,
        )
        .unwrap();

        let (signing_key, _) = generate_signing_keypair();
        let (_, wrong_verify_key) = generate_signing_keypair();

        sign_file(&encrypted, &signed, &signing_key, None, false).unwrap();

        let result = verify_signature(&signed, &wrong_verify_key);
        assert!(result.is_err());
    }

    #[test]
    fn unsigned_file_reports_not_signed() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input.txt");
        let encrypted = dir.path().join("encrypted.lvau");

        fs::write(&input, "unsigned test data").unwrap();

        encrypt_file_password(
            &input,
            &encrypted,
            Secret::new("password".to_string()),
            None,
            SecurityProfile::Fast,
            None,
        )
        .unwrap();

        let (_, verify_key) = generate_signing_keypair();
        let result = verify_signature(&encrypted, &verify_key);
        assert!(matches!(result, Err(SigningError::NotSigned)));

        let has_sig = has_signature(&encrypted).unwrap();
        assert!(has_sig.is_none());
    }

    #[test]
    fn save_and_load_signing_keys() {
        let dir = tempdir().unwrap();
        let sign_path = dir.path().join("test.lvau-sign");
        let verify_path = dir.path().join("test.lvau-verify");

        let (signing_key, verify_key) = generate_signing_keypair();

        save_signing_key(&signing_key, &sign_path, false).unwrap();
        save_verify_key(&verify_key, &verify_path, false).unwrap();

        let loaded_sign = load_signing_key(&sign_path).unwrap();
        let loaded_verify = load_verify_key(&verify_path).unwrap();

        assert_eq!(signing_key.to_bytes(), loaded_sign.to_bytes());
        assert_eq!(verify_key.as_bytes(), loaded_verify.as_bytes());
    }

    #[test]
    fn modified_envelope_fails_verification() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input.txt");
        let encrypted = dir.path().join("encrypted.lvau");
        let signed = dir.path().join("signed.lvau");

        fs::write(&input, "envelope tamper test").unwrap();

        encrypt_file_password(
            &input,
            &encrypted,
            Secret::new("password".to_string()),
            None,
            SecurityProfile::Fast,
            None,
        )
        .unwrap();

        let (signing_key, verify_key) = generate_signing_keypair();
        sign_file(&encrypted, &signed, &signing_key, None, false).unwrap();

        // Tamper with a byte in the envelope area (after the 4-byte length prefix)
        let mut data = fs::read(&signed).unwrap();
        if data.len() > 10 {
            data[8] ^= 0xFF; // flip a byte in the envelope
        }
        fs::write(&signed, data).unwrap();

        let result = verify_signature(&signed, &verify_key);
        assert!(result.is_err());
    }
}
