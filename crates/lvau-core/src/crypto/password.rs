use super::CryptoError;
use argon2::{password_hash::rand_core::OsRng, Argon2, Params};
use rand_core::RngCore;

pub struct PasswordAuth;

impl PasswordAuth {
    /// Generates a secure random 16-byte salt for password hashing.
    pub fn generate_salt() -> [u8; 16] {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        salt
    }

    /// Derives a 32-byte key from the password and salt using Argon2id.
    pub fn derive_key(password: &str, salt: &[u8; 16]) -> Result<[u8; 32], CryptoError> {
        let params = Params::new(
            Params::DEFAULT_M_COST,
            Params::DEFAULT_T_COST,
            Params::DEFAULT_P_COST,
            Some(32),
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        let mut key = [0u8; 32];
        match argon2.hash_password_into(password.as_bytes(), salt, &mut key) {
            Ok(_) => Ok(key),
            Err(_) => Err(CryptoError::DecryptionFailed),
        }
    }
}
