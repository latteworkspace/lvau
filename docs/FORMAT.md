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
}
```

(Note: `ciphertext` is no longer stored in the `Envelope` struct; chunks are streamed directly to the file after the envelope.)

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

## Compatibility Policy

Before v1.0, forward compatibility is not guaranteed. Breaking format changes must:

- update this document,
- update tests,
- be recorded in `CHANGELOG.md`,
- keep the version field meaningful for future migration.

After v1.0, format compatibility should follow semantic versioning.

## Security Notes

- Lvau does not use custom ciphers as a security boundary.
- The `extreme` profile includes LCO obfuscation. LCO is not a cryptographic security boundary.
- Public metadata includes algorithm, profile, KDF parameters, recipients, nonce values, ciphertext length, and plaintext length.
