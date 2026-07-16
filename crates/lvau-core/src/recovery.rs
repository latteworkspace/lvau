use crate::crypto::CryptoError;
use blahaj::{Share as SharksShare, Sharks};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;

const CURRENT_SHARE_VERSION: u32 = 2;
const MAX_SHARE_FILE_SIZE: usize = 1024 * 1024;

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
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let mut temp = NamedTempFile::new_in(parent)?;
        temp.write_all(&encoded)?;
        temp.as_file().sync_all()?;

        #[cfg(windows)]
        if path.exists() {
            fs::remove_file(path)?;
        }
        temp.persist(path)
            .map_err(|error| CryptoError::Io(error.error))?;

        #[cfg(unix)]
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    }

    pub fn from_file(path: &Path) -> Result<Self, CryptoError> {
        let bytes = fs::read(path)?;
        if bytes.len() > MAX_SHARE_FILE_SIZE {
            return Err(CryptoError::Validation("Recovery share is too large"));
        }
        let (share, remaining): (Self, &[u8]) = postcard::take_from_bytes(&bytes)?;
        if !remaining.is_empty() {
            return Err(CryptoError::Validation(
                "Recovery share contains trailing data",
            ));
        }
        if &share.magic != b"LVAU" {
            return Err(CryptoError::Validation("Invalid magic bytes in share"));
        }
        if !(1..=CURRENT_SHARE_VERSION).contains(&share.version) {
            return Err(CryptoError::Validation(
                "Unsupported recovery share version",
            ));
        }
        if share.threshold == 0 || share.share_data.first().copied() != Some(share.index) {
            return Err(CryptoError::Validation("Invalid recovery share metadata"));
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

    // Version 1 published SHA-256(secret), which enabled offline guesses for
    // low-entropy secrets. Version 2 uses a random set identifier instead.
    let mut fingerprint = [0u8; 32];
    OsRng.fill_bytes(&mut fingerprint);

    let mut result = Vec::new();
    for share in dealer.take(num_shares as usize) {
        let share_bytes = Vec::from(&share);

        let index = share_bytes[0];

        result.push(RecoveryShare {
            magic: *b"LVAU",
            version: CURRENT_SHARE_VERSION,
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
    let version = shares[0].version;

    if threshold == 0 || shares.len() < threshold as usize {
        return Err(CryptoError::Validation(
            "Not enough shares to reach threshold",
        ));
    }

    let mut indices = HashSet::new();
    for s in shares {
        if &s.magic != b"LVAU"
            || !(1..=CURRENT_SHARE_VERSION).contains(&s.version)
            || s.version != version
            || s.threshold != threshold
            || s.fingerprint != fingerprint
            || s.share_data.first().copied() != Some(s.index)
            || !indices.insert(s.index)
        {
            return Err(CryptoError::Validation(
                "Mismatched, duplicate, or invalid recovery shares",
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

    let recovered = sharks
        .recover(&sharks_shares)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    if version == 1 && <[u8; 32]>::from(Sha256::digest(&recovered)) != fingerprint {
        return Err(CryptoError::DecryptionFailed);
    }

    Ok(recovered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_shares_do_not_publish_a_secret_hash() {
        let secret = b"guessable password";
        let shares = split_secret(secret, 3, 2).unwrap();
        let secret_hash: [u8; 32] = Sha256::digest(secret).into();

        assert!(shares.iter().all(|share| share.version >= 2));
        assert!(shares.iter().all(|share| share.fingerprint != secret_hash));
    }

    #[test]
    fn legacy_share_fingerprint_is_checked_after_recovery() {
        let secret = b"legacy recovery secret";
        let mut shares = split_secret(secret, 3, 2).unwrap();
        for share in &mut shares {
            share.version = 1;
            share.fingerprint = [0xCC; 32];
        }

        assert!(combine_shares(&shares[..2]).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn recovery_share_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.lvau-share");
        let share = split_secret(b"secret", 2, 2).unwrap().remove(0);
        share.to_file(&path).unwrap();

        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
