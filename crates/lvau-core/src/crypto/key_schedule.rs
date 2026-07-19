//! Domain-separated key derivation for Lvau cryptographic purposes.

use super::CryptoError;
use hkdf::Hkdf;
use sha2::Sha256;

/// A cryptographic purpose with a fixed compatibility-sensitive HKDF label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPurpose {
    Payload,
    CascadeAes,
    CascadeXChaCha,
    LegacyLco,
    KeyWrap,
    EnvelopeCommitment,
    BundleManifest,
    Padding,
}

impl KeyPurpose {
    pub const fn label(self) -> &'static [u8] {
        match self {
            // Existing labels must remain byte-for-byte stable for format v2.
            Self::Payload => b"Lvau-file-encryption",
            Self::CascadeAes => b"Lvau-Cascade-AES",
            Self::CascadeXChaCha => b"Lvau-Cascade-XChaCha",
            Self::LegacyLco => b"Lvau-Cascade-LCO",
            Self::KeyWrap => b"Lvau-Key-Wrap",
            // Reserved, versioned domains for future format work.
            Self::EnvelopeCommitment => b"Lvau-v3-envelope-commitment",
            Self::BundleManifest => b"Lvau-v3-bundle-manifest",
            Self::Padding => b"Lvau-v3-padding",
        }
    }
}

/// Expand a 32-byte subkey for one purpose from an already extracted root key.
pub fn derive_subkey(
    hk: &Hkdf<Sha256>,
    purpose: KeyPurpose,
    out: &mut [u8; 32],
) -> Result<(), CryptoError> {
    hk.expand(purpose.label(), out)
        .map_err(|_| CryptoError::EncryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex_32(value: &str) -> [u8; 32] {
        assert_eq!(value.len(), 64);
        let mut out = [0u8; 32];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn labels_are_unique() {
        let purposes = [
            KeyPurpose::Payload,
            KeyPurpose::CascadeAes,
            KeyPurpose::CascadeXChaCha,
            KeyPurpose::LegacyLco,
            KeyPurpose::KeyWrap,
            KeyPurpose::EnvelopeCommitment,
            KeyPurpose::BundleManifest,
            KeyPurpose::Padding,
        ];
        for (index, left) in purposes.iter().enumerate() {
            for right in &purposes[index + 1..] {
                assert_ne!(left.label(), right.label());
            }
        }
    }

    #[test]
    fn compatibility_known_answer_vectors() {
        let hk = Hkdf::<Sha256>::new(None, &[0x42; 32]);
        let vectors = [
            (
                KeyPurpose::Payload,
                "859b1bbbe148c294877d5570be585179cc9e8af682b1b3abf86792be787d6d1e",
            ),
            (
                KeyPurpose::CascadeAes,
                "d34289e49c23638f794f22bbe52fc215eadbe3511477c4ef5b0d85e18f525e4d",
            ),
            (
                KeyPurpose::CascadeXChaCha,
                "49635e89a91ed1c90809b8a4e19852db65daca854fb7994e87c80eaa6ec341db",
            ),
            (
                KeyPurpose::LegacyLco,
                "87cb9f3dbe9e5e32a9c7588cc97dc37e59a609fdbbfbda600ddc14d89d543074",
            ),
            (
                KeyPurpose::KeyWrap,
                "df296ea9fba90970f96a3e77893a46f1b5d7069f5800e176c270f9489125b944",
            ),
        ];

        for (purpose, expected) in vectors {
            let mut actual = [0u8; 32];
            derive_subkey(&hk, purpose, &mut actual).unwrap();
            assert_eq!(actual, decode_hex_32(expected));
        }
    }
}
