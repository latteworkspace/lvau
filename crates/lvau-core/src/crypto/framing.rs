//! Compatibility-sensitive nonce and chunk-AAD construction.

use super::CryptoError;

/// Derive the per-chunk XChaCha nonce used by format v2.
pub fn xchacha_nonce(base: &[u8; 24], chunk_index: u64) -> [u8; 24] {
    let mut nonce = *base;
    for (slot, index_byte) in nonce[..8].iter_mut().zip(chunk_index.to_le_bytes()) {
        *slot ^= index_byte;
    }
    nonce
}

/// Derive the per-chunk AES nonce used by format v2 cascade suites.
pub fn aes_nonce(base: &[u8; 12], chunk_index: u64) -> [u8; 12] {
    let mut nonce = *base;
    for (slot, index_byte) in nonce[..8].iter_mut().zip(chunk_index.to_le_bytes()) {
        *slot ^= index_byte;
    }
    nonce
}

/// Construct format-v2 chunk AAD as commitment hash followed by LE chunk index.
pub fn chunk_aad(commitment: &[u8; 32], chunk_index: u64) -> [u8; 40] {
    let mut aad = [0u8; 40];
    aad[..32].copy_from_slice(commitment);
    aad[32..].copy_from_slice(&chunk_index.to_le_bytes());
    aad
}

/// Reject index arithmetic that would wrap a chunk counter.
pub fn checked_next_chunk(chunk_index: u64) -> Result<u64, CryptoError> {
    chunk_index
        .checked_add(1)
        .ok_or(CryptoError::Validation("Chunk index overflow"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_and_aad_vectors_are_stable() {
        let x_base = [0xA5; 24];
        let a_base = [0x5A; 12];
        let commitment = [0x11; 32];
        let index = 0x0102_0304_0506_0708;

        assert_eq!(
            &xchacha_nonce(&x_base, index)[..8],
            &[0xAD, 0xA2, 0xA3, 0xA0, 0xA1, 0xA6, 0xA7, 0xA4]
        );
        assert_eq!(
            &aes_nonce(&a_base, index)[..8],
            &[0x52, 0x5D, 0x5C, 0x5F, 0x5E, 0x59, 0x58, 0x5B]
        );
        assert_eq!(&chunk_aad(&commitment, index)[32..], &index.to_le_bytes());
    }

    #[test]
    fn chunk_counter_overflow_fails_closed() {
        assert!(checked_next_chunk(u64::MAX).is_err());
    }
}
