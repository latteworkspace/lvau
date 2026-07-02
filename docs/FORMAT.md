# `.lvau` Envelope Format

This document describes the `.lvau` format implemented by `lvau-protocol` and `lvau-core`.

> The `.lvau` format is not stable before v1.0.

## Encoding

A `.lvau` file is one postcard-serialized `Envelope` value. Postcard is compact and version-sensitive, so the byte layout is tied to the Rust data structures and postcard version used by Lvau v0.1.0.

## Envelope Fields

```rust
pub struct Envelope {
    pub header: EnvelopeHeader,
    pub plaintext_len: u64,
    pub nonce: [u8; 24],
    pub secondary_nonce: Option<[u8; 12]>,
    pub aad_hash: [u8; 32],
    pub ciphertext: Vec<u8>,
    pub metadata: Vec<u8>,
}
```

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

The postcard-serialized header is hashed with SHA-256. The resulting `aad_hash` is passed as AEAD additional authenticated data for every encrypted chunk. Decryptors recompute the hash and reject mismatches before payload decryption.

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

Each chunk is independently authenticated. The header hash is used as AAD for each chunk.

### Recipients

```rust
pub enum Recipient {
    Password,
    X25519MlkemHybrid {
        ephemeral_public_x25519: [u8; 32],
        mlkem_ciphertext: Vec<u8>,
        encrypted_file_key: Vec<u8>,
    },
}
```

`Password` indicates password-derived encryption. `X25519MlkemHybrid` is experimental and combines X25519 and ML-KEM-768 shared secrets through HKDF.

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

## Known Limitations (v0.1.0)

- **Chunk index not in AAD**: Each chunk uses the header hash as AEAD AAD, but the chunk index is not included. Chunk reordering within a file would be detected by the plaintext length check and by nonce-derived chunk boundaries, but adding the chunk index to AAD would provide a stronger guarantee. This is planned for v0.2.0.
- **Entire files in memory**: Lvau currently reads entire files into memory before encryption or decryption.
