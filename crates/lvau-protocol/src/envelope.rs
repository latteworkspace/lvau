use serde::{Deserialize, Serialize};

pub const MAGIC_REAL: [u8; 4] = *b"LVAU";
pub const CURRENT_VERSION: u16 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SecurityProfile {
    Fast,
    Balanced,
    Archive,
    Paranoid,
    Extreme,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum AlgorithmId {
    XChaCha20Poly1305,
    CascadeAesGcmXChaCha,
    TripleCascadeAesXChaChaLco,
    X25519,
    Ed25519,
    X25519MlkemHybrid,
    Ed25519MldsaHybrid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KdfParams {
    Argon2id {
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
        salt: [u8; 16],
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Recipient {
    Password, // indicates the file uses KdfParams to derive key
    X25519MlkemHybrid {
        ephemeral_public_x25519: [u8; 32],
        mlkem_ciphertext: Vec<u8>,
        encrypted_file_key: Vec<u8>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeHeader {
    pub magic: [u8; 4],
    pub version: u16,
    pub profile: SecurityProfile,
    pub algorithm: AlgorithmId,
    pub kdf: Option<KdfParams>,
    pub recipients: Vec<Recipient>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub header: EnvelopeHeader,
    pub nonce: [u8; 24],
    pub secondary_nonce: Option<[u8; 12]>,
    pub aad_hash: [u8; 32],
    pub ciphertext: Vec<u8>,
    pub metadata: Vec<u8>, // encrypted or minimal public metadata
}

impl Envelope {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.header.magic != MAGIC_REAL {
            return Err("Invalid magic bytes, not a Lvau file");
        }
        if self.header.version != CURRENT_VERSION {
            return Err("Unsupported format version");
        }
        Ok(())
    }
}
