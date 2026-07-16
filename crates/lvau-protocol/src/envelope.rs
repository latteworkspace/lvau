use serde::{Deserialize, Serialize};

pub const MAGIC_REAL: [u8; 4] = *b"LVAU";
pub const LEGACY_VERSION: u16 = 1;
pub const CURRENT_VERSION: u16 = 2;

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
    Password {
        nonce: [u8; 24],
        encrypted_file_key: Vec<u8>,
    }, // indicates the file uses KdfParams to derive key which wraps the FEK
    X25519MlkemHybrid {
        ephemeral_public_x25519: [u8; 32],
        mlkem_ciphertext: Vec<u8>,
        encrypted_file_key: Vec<u8>,
    },
}

/// Distinguishes between single-file encryption and directory bundles.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ContentType {
    /// Default single-file encryption (v0.2.x behavior).
    SingleFile,
    /// Directory bundle with an encrypted manifest.
    Bundle,
}

/// Ed25519 signature covering the envelope and ciphertext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeSignature {
    /// SHA-256 fingerprint of the signer's Ed25519 public key.
    pub signer_fingerprint: [u8; 32],
    /// 64-byte Ed25519 signature.
    pub signature: Vec<u8>,
    /// ISO 8601 timestamp of when the signature was created, if available.
    #[serde(default)]
    pub created_at: Option<String>,
    /// Optional comment from the signer.
    #[serde(default)]
    pub comment: Option<String>,
}

/// An approval seal from a third-party, signing the public envelope AAD hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalSignature {
    pub signer_fingerprint: [u8; 32],
    pub signature: Vec<u8>,
    #[serde(default)]
    pub comment: Option<String>,
}

/// Release metadata indicating provenance.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReleaseMetadata {
    #[serde(default)]
    pub project_name: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub git_commit: Option<String>,
    #[serde(default)]
    pub build_timestamp: Option<String>,
}

/// Entry in a bundle manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleEntry {
    /// Relative path within the bundle (forward slashes, no leading /).
    pub relative_path: String,
    /// File size in bytes.
    pub size: u64,
    /// BLAKE3 hash of the file contents.
    pub blake3_hash: [u8; 32],
    /// Byte offset within the concatenated file content blob.
    pub offset: u64,
}

/// Manifest for a directory bundle, encrypted as part of the payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleManifest {
    pub entries: Vec<BundleEntry>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub tool_version: Option<String>,
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
    pub plaintext_len: u64,
    pub nonce: [u8; 24],
    pub secondary_nonce: Option<[u8; 12]>,
    pub aad_hash: [u8; 32],
    pub metadata: Vec<u8>, // encrypted or minimal public metadata

    // Optional fields default for legacy v0.2 envelope decoding.
    /// Content type: SingleFile or Bundle. None is treated as SingleFile.
    #[serde(default)]
    pub content_type: Option<ContentType>,
    /// Optional Ed25519 signature covering the envelope and ciphertext.
    #[serde(default)]
    pub signature: Option<EnvelopeSignature>,
    /// Optional user-provided label visible in public inspect output.
    #[serde(default)]
    pub public_label: Option<String>,

    // Mutable workflow annotations are intentionally outside payload AAD.
    #[serde(default)]
    pub approvals: Vec<ApprovalSignature>,

    #[serde(default)]
    pub release_metadata: Option<ReleaseMetadata>,
    #[serde(default)]
    pub policy_overridden: bool,
    #[serde(default)]
    pub recovery_metadata: Option<Vec<u8>>,
}

impl Envelope {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.header.magic != MAGIC_REAL {
            return Err("Invalid magic bytes, not a Lvau file");
        }
        if !(LEGACY_VERSION..=CURRENT_VERSION).contains(&self.header.version) {
            return Err("Unsupported format version");
        }
        Ok(())
    }

    /// Returns the effective content type, defaulting to SingleFile for legacy envelopes.
    pub fn effective_content_type(&self) -> ContentType {
        self.content_type.clone().unwrap_or(ContentType::SingleFile)
    }
}
