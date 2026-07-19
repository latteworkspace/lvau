//! Versioned cryptographic-suite metadata.
//!
//! The registry describes wire-format capabilities without selecting new
//! algorithms implicitly from broad security-profile names. Format v2 keeps its
//! historical identifiers and byte layout; future formats must allocate new
//! suite identifiers rather than reinterpret an existing one.

use lvau_protocol::envelope::AlgorithmId;

/// Stable internal identifier for a payload suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SuiteId {
    V2XChaCha20Poly1305,
    V2AesGcmXChaCha20Poly1305,
    V2AesGcmXChaCha20Poly1305Lco,
}

/// Capabilities and framing constraints for a payload suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoSuite {
    pub id: SuiteId,
    pub format_version: u16,
    pub layer_count: u8,
    pub xchacha_nonce_len: usize,
    pub aes_nonce_len: Option<usize>,
    pub tag_overhead_per_chunk: usize,
    pub experimental: bool,
    pub includes_legacy_obfuscation: bool,
}

impl CryptoSuite {
    /// Resolve an existing v2 payload algorithm without changing its meaning.
    pub fn for_v2_algorithm(algorithm: &AlgorithmId) -> Option<Self> {
        match algorithm {
            AlgorithmId::XChaCha20Poly1305 => Some(Self {
                id: SuiteId::V2XChaCha20Poly1305,
                format_version: 2,
                layer_count: 1,
                xchacha_nonce_len: 24,
                aes_nonce_len: None,
                tag_overhead_per_chunk: 16,
                experimental: false,
                includes_legacy_obfuscation: false,
            }),
            AlgorithmId::CascadeAesGcmXChaCha => Some(Self {
                id: SuiteId::V2AesGcmXChaCha20Poly1305,
                format_version: 2,
                layer_count: 2,
                xchacha_nonce_len: 24,
                aes_nonce_len: Some(12),
                tag_overhead_per_chunk: 32,
                experimental: true,
                includes_legacy_obfuscation: false,
            }),
            AlgorithmId::TripleCascadeAesXChaChaLco => Some(Self {
                id: SuiteId::V2AesGcmXChaCha20Poly1305Lco,
                format_version: 2,
                // LCO is reversible obfuscation, not an encryption layer.
                layer_count: 2,
                xchacha_nonce_len: 24,
                aes_nonce_len: Some(12),
                tag_overhead_per_chunk: 32,
                experimental: true,
                includes_legacy_obfuscation: true,
            }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_lco_is_not_counted_as_a_cipher_layer() {
        let suite = CryptoSuite::for_v2_algorithm(&AlgorithmId::TripleCascadeAesXChaChaLco)
            .expect("registered v2 suite");
        assert_eq!(suite.layer_count, 2);
        assert!(suite.includes_legacy_obfuscation);
    }

    #[test]
    fn recipient_and_signature_ids_are_not_payload_suites() {
        assert!(CryptoSuite::for_v2_algorithm(&AlgorithmId::X25519MlkemHybrid).is_none());
        assert!(CryptoSuite::for_v2_algorithm(&AlgorithmId::Ed25519).is_none());
    }
}
