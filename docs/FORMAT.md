# `.lvau` Envelope Format

This document describes the `.lvau` format implemented by `lvau-protocol` and `lvau-core`.

> The `.lvau` format is not stable before v1.0.

## Encoding

Lvau uses a streaming architecture for large file support. A `.lvau` file consists of:

1. A 4-byte little-endian unsigned integer (`u32`) representing the length of the serialized `Envelope` header.
2. The postcard-serialized `Envelope` value.
3. The concatenated encrypted payload chunks.

Postcard is compact and version-sensitive, so the byte layout is tied to the Rust data structures and postcard version used by Lvau.

## Envelope Fields

```rust
pub struct Envelope {
    pub header: EnvelopeHeader,
    pub plaintext_len: u64,
    pub nonce: [u8; 24],
    pub secondary_nonce: Option<[u8; 12]>,
    pub aad_hash: [u8; 32],
    pub metadata: Vec<u8>,
    pub content_type: Option<ContentType>,    // v0.3.0+
    pub signature: Option<EnvelopeSignature>, // v0.3.0+
    pub public_label: Option<String>,         // v0.3.0+
}
```

(Note: `ciphertext` is no longer stored in the `Envelope` struct; chunks are streamed directly to the file after the envelope.)

### New fields (v0.3.0)

- `content_type`: Distinguishes between `SingleFile` and `Bundle` payloads. Absent (or `None`) for v0.2.x files, which are treated as `SingleFile`.
- `signature`: Optional Ed25519 signature covering the envelope and ciphertext. See "Signatures" section below.
- `public_label`: Optional user-provided label visible in public inspect output. Only set when the user explicitly passes `--public-label`.

### Backward Compatibility

All new fields are `Option<T>` with `#[serde(default)]`. Files created by v0.2.x will deserialize with `None` for these fields. v0.3.0 can read v0.2.x files without errors.

### Header

```rust
pub struct EnvelopeHeader {
    pub magic: [u8; 4],
    pub version: u16,
    pub profile: SecurityProfile,
    pub algorithm: AlgorithmId,
    pub kdf: Option<KdfParams>,
    pub recipients: Vec<Recipient>,
}
```

- `magic`: `LVAU` (`0x4c 0x56 0x41 0x55`)
- `version`: currently `1`
- `profile`: selected security profile
- `algorithm`: payload algorithm identifier
- `kdf`: Argon2id parameters for password encryption, absent for keypair encryption
- `recipients`: password marker or experimental hybrid keypair recipient data

The postcard-serialized header is hashed with SHA-256. The resulting `aad_hash` is passed as AEAD additional authenticated data for every encrypted chunk, along with the global chunk index. Decryptors recompute the hash and reject mismatches before payload decryption.

### Plaintext Length

`plaintext_len` is public metadata containing the original plaintext length in bytes. It is checked after decryption so whole-chunk truncation cannot silently produce a shorter plaintext.

### KDF Parameters

```rust
pub enum KdfParams {
    Argon2id {
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
        salt: [u8; 16],
    },
}
```

The salt is generated with `OsRng` for each encryption.

| Profile | `m_cost` | `t_cost` | `p_cost` |
| --- | ---: | ---: | ---: |
| `Fast` | 16384 | 1 | 1 |
| `Balanced` | 65536 | 2 | 1 |
| `Archive` | 262144 | 3 | 2 |
| `Paranoid` | 1048576 | 4 | 4 |
| `Extreme` | 1048576 | 4 | 4 |

### Nonces

- `nonce`: 24-byte XChaCha20-Poly1305 base nonce.
- `secondary_nonce`: 12-byte AES-GCM base nonce for cascade profiles.

For each 1 MiB chunk, Lvau derives a chunk nonce by XORing the little-endian chunk index into the first four bytes of the base nonce.

### Ciphertext Layout

Payloads are split into 1 MiB chunks.

| Algorithm | Profile | Per-chunk overhead |
| --- | --- | ---: |
| `XChaCha20Poly1305` | `fast`, `balanced`, `archive` | 16 bytes |
| `CascadeAesGcmXChaCha` | `paranoid` | 32 bytes |
| `TripleCascadeAesXChaChaLco` | `extreme` | 32 bytes |

Each chunk is independently authenticated. The AAD for each chunk consists of the header `aad_hash` appended with the 64-bit little-endian global chunk index. This prevents chunk reordering or swapping.

### Recipients

```rust
pub enum Recipient {
    Password {
        nonce: [u8; 24],
        encrypted_file_key: Vec<u8>,
    },
    X25519MlkemHybrid {
        ephemeral_public_x25519: [u8; 32],
        mlkem_ciphertext: Vec<u8>,
        encrypted_file_key: Vec<u8>,
    },
}
```

`Password` indicates password-derived encryption where the FEK (File Encryption Key) is wrapped with XChaCha20-Poly1305. `X25519MlkemHybrid` is experimental and combines X25519 and ML-KEM-768 shared secrets through HKDF.

## Content Types (v0.3.0)

```rust
pub enum ContentType {
    SingleFile,
    Bundle,
}
```

- `SingleFile`: The payload is a single encrypted file (default for v0.2.x compatibility).
- `Bundle`: The payload is a serialized bundle containing a manifest and multiple files.

### Bundle Payload Format

When `content_type` is `Bundle`, the encrypted payload has the following structure:

1. A postcard-serialized `BundleManifest` (length-prefixed).
2. Concatenated file contents in manifest order.

```rust
pub struct BundleManifest {
    pub entries: Vec<BundleEntry>,
    pub created_at: Option<String>,
    pub tool_version: Option<String>,
}

pub struct BundleEntry {
    pub relative_path: String,
    pub size: u64,
    pub blake3_hash: [u8; 32],
    pub offset: u64,
}
```

The entire bundle payload (manifest + file contents) is encrypted as a single payload using the same chunk-based AEAD as single-file encryption.

## Signatures (v0.3.0)

```rust
pub struct EnvelopeSignature {
    pub signer_fingerprint: [u8; 32],
    pub signature: Vec<u8>,  // 64-byte Ed25519 signature
    pub created_at: Option<String>,
    pub comment: Option<String>,
}
```

### Signing process

1. Serialize the envelope without the `signature` field.
2. Concatenate the serialized envelope bytes with all ciphertext bytes.
3. Sign the concatenated bytes with the Ed25519 signing key.
4. Store the signature in the `signature` field.
5. Re-serialize the envelope with the signature.

### Verification process

1. Read the envelope and extract the signature.
2. Set the `signature` field to `None`.
3. Re-serialize the envelope without the signature.
4. Concatenate with all ciphertext bytes.
5. Verify the Ed25519 signature against the concatenated bytes.

Verification does not require the decryption password or private key.

> **Note**: Ed25519 signatures and AEAD authentication serve different purposes. See [THREAT_MODEL.md](THREAT_MODEL.md) for details.

## Compatibility Policy

Before v1.0, forward compatibility is not guaranteed. Breaking format changes must:

- update this document,
- update tests,
- be recorded in `CHANGELOG.md`,
- keep the version field meaningful for future migration.

After v1.0, format compatibility should follow semantic versioning.

### v0.2.x → v0.3.0 Compatibility

- v0.3.0 can read v0.2.x files. New `Option` fields default to `None`.
- v0.2.x cannot read v0.3.0 files that use new fields (they will fail at deserialization).
- The `version` field remains `1` for now. A version bump to `2` is reserved for truly breaking changes.

## Security Notes

- Lvau does not use custom ciphers as a security boundary.
- The `extreme` profile includes LCO obfuscation. LCO is not a cryptographic security boundary.
- Public metadata includes algorithm, profile, KDF parameters, recipients, nonce values, ciphertext length, and plaintext length.
- Bundle mode does not expose internal file names or directory structure in public metadata by default.
- Signatures use Ed25519 from the `ed25519-dalek` crate.
