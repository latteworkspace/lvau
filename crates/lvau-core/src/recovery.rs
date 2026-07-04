use crate::crypto::CryptoError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sharks::{Share as SharksShare, Sharks};
use std::fs;
use std::path::Path;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RecoveryShare {
    pub magic: [u8; 4],
    pub version: u32,
    pub index: u8,
    pub threshold: u8,
    pub fingerprint: [u8; 32],
    pub share_data: Vec<u8>,
}

impl RecoveryShare {
    pub fn to_file(&self, path: &Path) -> Result<(), CryptoError> {
        let encoded = postcard::to_allocvec(self)?;
        fs::write(path, encoded)?;
        Ok(())
    }

    pub fn from_file(path: &Path) -> Result<Self, CryptoError> {
        let bytes = fs::read(path)?;
        let share: Self = postcard::from_bytes(&bytes)?;
        if &share.magic != b"LVAU" {
            return Err(CryptoError::Validation("Invalid magic bytes in share"));
        }
        Ok(share)
    }
}

pub fn split_secret(
    secret: &[u8],
    num_shares: u8,
    threshold: u8,
) -> Result<Vec<RecoveryShare>, CryptoError> {
    if threshold == 0 || num_shares == 0 || threshold > num_shares {
        return Err(CryptoError::Validation("Invalid threshold or share count"));
    }

    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(secret);

    let mut fingerprint = [0u8; 32];
    let mut hasher = Sha256::new();
    hasher.update(secret);
    fingerprint.copy_from_slice(&hasher.finalize());

    let mut result = Vec::new();
    for share in dealer.take(num_shares as usize) {
        let share_bytes = Vec::from(&share);

        let index = share_bytes[0];

        result.push(RecoveryShare {
            magic: *b"LVAU",
            version: 1,
            index,
            threshold,
            fingerprint,
            share_data: share_bytes,
        });
    }

    Ok(result)
}

pub fn combine_shares(shares: &[RecoveryShare]) -> Result<Vec<u8>, CryptoError> {
    if shares.is_empty() {
        return Err(CryptoError::Validation("No shares provided"));
    }

    let threshold = shares[0].threshold;
    let fingerprint = shares[0].fingerprint;

    if shares.len() < threshold as usize {
        return Err(CryptoError::Validation(
            "Not enough shares to reach threshold",
        ));
    }

    for s in shares {
        if s.threshold != threshold || s.fingerprint != fingerprint {
            return Err(CryptoError::Validation(
                "Mismatched shares (different thresholds or fingerprints)",
            ));
        }
    }

    let sharks = Sharks(threshold);

    let mut sharks_shares = Vec::new();
    for s in shares {
        let sharks_share = SharksShare::try_from(s.share_data.as_slice())
            .map_err(|_| CryptoError::Validation("Invalid share data format"))?;
        sharks_shares.push(sharks_share);
    }

    sharks
        .recover(&sharks_shares)
        .map_err(|_| CryptoError::DecryptionFailed)
}
