use base64::Engine;
use kem::Kem as KemTrait;
use ml_kem::{DecapsulationKey768, EncapsulationKey768, MlKem768};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use kem::KeyExport;

use crate::crypto::CryptoError;

type Kem = MlKem768;

#[derive(Serialize, Deserialize, Debug)]
pub struct HybridPublicKeyFormat {
    pub x25519_pub: String,
    pub mlkem_pub: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HybridPrivateKeyFormat {
    pub x25519_priv: String,
    pub mlkem_priv: String,
}

pub struct HybridPublicKey {
    pub x25519: X25519PublicKey,
    pub mlkem: EncapsulationKey768,
}

pub struct HybridPrivateKey {
    pub x25519: StaticSecret,
    pub mlkem: DecapsulationKey768,
}

pub fn generate_keypair() -> (HybridPrivateKey, HybridPublicKey) {
    let mut rng = OsRng;

    // Generate X25519 Keypair
    let x25519_priv = StaticSecret::random_from_rng(&mut rng);
    let x25519_pub = X25519PublicKey::from(&x25519_priv);

    // Generate ML-KEM-768 Keypair
    let (mlkem_priv, mlkem_pub) = Kem::generate_keypair();

    let priv_key = HybridPrivateKey {
        x25519: x25519_priv,
        mlkem: mlkem_priv,
    };

    let pub_key = HybridPublicKey {
        x25519: x25519_pub,
        mlkem: mlkem_pub,
    };

    (priv_key, pub_key)
}

impl HybridPublicKey {
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), CryptoError> {
        let x25519_b64 = base64::engine::general_purpose::STANDARD.encode(self.x25519.as_bytes());
        
        // mlkem.to_bytes() returns a GenericArray for the EncapsulationKey
        let mlkem_b64 = base64::engine::general_purpose::STANDARD.encode(self.mlkem.to_bytes().as_slice());

        let format = HybridPublicKeyFormat {
            x25519_pub: x25519_b64,
            mlkem_pub: mlkem_b64,
        };

        let json = serde_json::to_string_pretty(&format).map_err(|_| CryptoError::DecryptionFailed)?;
        fs::write(path, json).map_err(|_| CryptoError::Io(std::io::Error::new(std::io::ErrorKind::Other, "IO Error")))?;
        Ok(())
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, CryptoError> {
        let json = fs::read_to_string(path).map_err(|_| CryptoError::Io(std::io::Error::new(std::io::ErrorKind::Other, "IO Error")))?;
        let format: HybridPublicKeyFormat = serde_json::from_str(&json).map_err(|_| CryptoError::DecryptionFailed)?;

        let x25519_bytes = base64::engine::general_purpose::STANDARD.decode(&format.x25519_pub).map_err(|_| CryptoError::DecryptionFailed)?;
        let mlkem_bytes = base64::engine::general_purpose::STANDARD.decode(&format.mlkem_pub).map_err(|_| CryptoError::DecryptionFailed)?;

        if x25519_bytes.len() != 32 {
            return Err(CryptoError::DecryptionFailed);
        }

        let mut x_arr = [0u8; 32];
        x_arr.copy_from_slice(&x25519_bytes);
        let x25519 = X25519PublicKey::from(x_arr);

        // Load ML-KEM EncapsulationKey
        let enc_arr: [u8; 1184] = mlkem_bytes.try_into().map_err(|_| CryptoError::DecryptionFailed)?;
        let mlkem = EncapsulationKey768::new(&enc_arr.into()).map_err(|_| CryptoError::DecryptionFailed)?;

        Ok(Self { x25519, mlkem })
    }
}

impl HybridPrivateKey {
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), CryptoError> {
        let x25519_b64 = base64::engine::general_purpose::STANDARD.encode(self.x25519.to_bytes());
        
        // mlkem.to_bytes() returns the 64-byte seed for the DecapsulationKey
        let mlkem_b64 = base64::engine::general_purpose::STANDARD.encode(self.mlkem.to_bytes().as_slice());

        let format = HybridPrivateKeyFormat {
            x25519_priv: x25519_b64,
            mlkem_priv: mlkem_b64,
        };

        let json = serde_json::to_string_pretty(&format).map_err(|_| CryptoError::DecryptionFailed)?;
        fs::write(path, json).map_err(|_| CryptoError::Io(std::io::Error::new(std::io::ErrorKind::Other, "IO Error")))?;
        Ok(())
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, CryptoError> {
        let json = fs::read_to_string(path).map_err(|_| CryptoError::Io(std::io::Error::new(std::io::ErrorKind::Other, "IO Error")))?;
        let format: HybridPrivateKeyFormat = serde_json::from_str(&json).map_err(|_| CryptoError::DecryptionFailed)?;

        let x25519_bytes = base64::engine::general_purpose::STANDARD.decode(&format.x25519_priv).map_err(|_| CryptoError::DecryptionFailed)?;
        let mlkem_bytes = base64::engine::general_purpose::STANDARD.decode(&format.mlkem_priv).map_err(|_| CryptoError::DecryptionFailed)?;

        if x25519_bytes.len() != 32 {
            return Err(CryptoError::DecryptionFailed);
        }

        let mut x_arr = [0u8; 32];
        x_arr.copy_from_slice(&x25519_bytes);
        let x25519 = StaticSecret::from(x_arr);

        // Load ML-KEM DecapsulationKey from seed
        let seed_arr: [u8; 64] = mlkem_bytes.try_into().map_err(|_| CryptoError::DecryptionFailed)?;
        let mlkem = DecapsulationKey768::from_seed(seed_arr.into());

        Ok(Self { x25519, mlkem })
    }
}
