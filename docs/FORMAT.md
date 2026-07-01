# `.lvau` Envelope Format

This document describes the binary format of `.lvau` encrypted files as implemented in `lvau-protocol` and `lvau-core`.

> **Format stability:** The `.lvau` format is **not yet stable before v1.0**. Breaking changes may occur between minor versions. Do not rely on forward compatibility until v1.0.

## Overview

A `.lvau` file is a single binary blob containing a serialized `Envelope` struct. The serialization format is [postcard](https://crates.io/crates/postcard) — a compact, `no_std`-compatible binary format for Serde types.

## Conceptual structure

```
┌─────────────────────────────────────────────┐
│ Envelope (postcard-serialized)              │
│                                             │
│  ┌─────────────────────────────────────┐    │
│  │ EnvelopeHeader                      │    │
│  │  ├─ magic: [u8; 4]    = "LVAU"     │    │
│  │  ├─ version: u16      = 1          │    │
│  │  ├─ profile: SecurityProfile       │    │
│  │  ├─ algorithm: AlgorithmId         │    │
│  │  ├─ kdf: Option<KdfParams>         │    │
│  │  └─ recipients: Vec<Recipient>     │    │
│  └─────────────────────────────────────┘    │
│                                             │
│  nonce: [u8; 24]                            │
│  secondary_nonce: Option<[u8; 12]>          │
│  aad_hash: [u8; 32]                         │
│  ciphertext: Vec<u8>                        │
│  metadata: Vec<u8>                          │
└─────────────────────────────────────────────┘
```

## Field descriptions

### Magic bytes

```
magic: [u8; 4] = [0x4C, 0x56, 0x41, 0x55]  // "LVAU"
```

Identifies the file as a Lvau envelope. Validation rejects files that do not start with this magic (after postcard deserialization).

### Version

```
version: u16 = 1
```

The envelope format version. Currently only version `1` is supported. Files with unsupported versions are rejected at validation time.

### Security profile

```rust
enum SecurityProfile {
    Fast,       // Argon2id: 16 MB, 1 iteration, 1 thread
    Balanced,   // Argon2id: 64 MB, 2 iterations, 1 thread
    Archive,    // Argon2id: 256 MB, 3 iterations, 2 threads
    Paranoid,   // Argon2id: 1 GB, 4 iterations, 4 threads
    Extreme,    // Same Argon2id as Paranoid + triple cascade
}
```

Controls the KDF cost parameters and, for `Paranoid`/`Extreme`, the encryption algorithm cascade.

### Algorithm ID

```rust
enum AlgorithmId {
    XChaCha20Poly1305,          // Default for Fast, Balanced, Archive
    CascadeAesGcmXChaCha,       // Used by Paranoid profile
    TripleCascadeAesXChaChaLco, // Used by Extreme profile
    X25519,                     // Reserved
    Ed25519,                    // Reserved
    X25519MlkemHybrid,          // Hybrid key exchange
    Ed25519MldsaHybrid,         // Reserved
}
```

Determines which encryption algorithm(s) are applied to the payload.

### KDF parameters

```rust
enum KdfParams {
    Argon2id {
        m_cost: u32,     // Memory cost in KiB
        t_cost: u32,     // Number of iterations
        p_cost: u32,     // Degree of parallelism
        salt: [u8; 16],  // Random salt (unique per encryption)
    },
}
```

Present for password-based encryption. Absent (`None`) for keypair-based encryption.

The salt is generated fresh for each encryption using `OsRng`.

### Recipients

```rust
enum Recipient {
    Password,
    X25519MlkemHybrid {
        ephemeral_public_x25519: [u8; 32],
        mlkem_ciphertext: Vec<u8>,
        encrypted_file_key: Vec<u8>,
    },
}
```

- `Password`: indicates the file was encrypted with a password-derived key via KDF
- `X25519MlkemHybrid`: contains the ephemeral public key and ML-KEM ciphertext for hybrid decapsulation

### Nonce

```
nonce: [u8; 24]
```

The 192-bit nonce for XChaCha20-Poly1305. Generated randomly using `OsRng` for each encryption operation.

For chunked encryption, each chunk derives its own nonce by XORing the base nonce with the chunk index (as a little-endian u32 in the first 4 bytes).

### Secondary nonce

```
secondary_nonce: Option<[u8; 12]>
```

Present only for cascade algorithms (`CascadeAesGcmXChaCha`, `TripleCascadeAesXChaChaLco`). This 96-bit nonce is used for the AES-256-GCM layer. Per-chunk derivation uses the same index XOR scheme.

### AAD hash

```
aad_hash: [u8; 32]
```

SHA-256 hash of the postcard-serialized `EnvelopeHeader`. This hash is used as additional authenticated data (AAD) for the AEAD encryption, binding the header contents to the ciphertext.

### Ciphertext

```
ciphertext: Vec<u8>
```

The AEAD-encrypted payload. For large files, the plaintext is split into 1 MB (1,048,576 byte) chunks, each encrypted independently with a derived per-chunk nonce. The AEAD tag is appended to each chunk:

- XChaCha20-Poly1305: +16 bytes per chunk
- Cascade (AES-GCM + XChaCha20): +32 bytes per chunk (16 from each layer)

The last chunk may be smaller than 1 MB.

### Metadata

```
metadata: Vec<u8>
```

Reserved field for future use. Currently an empty vector. May be used for encrypted or plaintext metadata in future versions.

## Key derivation flow (password-based)

```
Password
   │
   ▼
Argon2id(password, salt, m_cost, t_cost, p_cost)
   │
   ▼
Master Key (32 bytes, zeroized after use)
   │
   ▼
HKDF-SHA256(master_key, info=<algorithm-specific>)
   │
   ▼
File Encryption Key(s) (32 bytes each)
```

HKDF info strings:
- `b"Lvau-file-encryption"` — for XChaCha20-Poly1305
- `b"Lvau-Cascade-AES"` — for AES-256-GCM layer
- `b"Lvau-Cascade-XChaCha"` — for XChaCha20-Poly1305 layer
- `b"Lvau-Cascade-LCO"` — for LCO obfuscation layer

## Key derivation flow (hybrid keypair)

```
Ephemeral X25519 + Recipient X25519 → X25519 shared secret
Recipient ML-KEM-768 → ML-KEM shared secret
   │
   ▼
Concatenate(X25519 SS, ML-KEM SS)
   │
   ▼
HKDF-SHA256(combined_ss, info=b"Lvau-Hybrid-Payload")
   │
   ▼
File Encryption Key (32 bytes)
```

## Serialization

The entire `Envelope` struct is serialized using [postcard](https://crates.io/crates/postcard) with `postcard::to_allocvec()` and deserialized with `postcard::from_bytes()`.

Postcard uses a compact varint encoding for lengths and enum variants. The exact byte layout depends on the postcard version and the data sizes. This is why the format is tied to the postcard crate version and is not yet stable.

## Forward and backward compatibility

- **Forward compatibility**: Not guaranteed before v1.0. New versions may change the envelope structure.
- **Backward compatibility**: Version 1 files will be readable by any Lvau version that supports version 1.
- **Version negotiation**: The `version` field in the header allows future versions to implement migration logic.

## Format stability policy

The `.lvau` format will be considered stable at **v1.0**. Until then:

- Breaking format changes will be documented in the [CHANGELOG](../CHANGELOG.md)
- The version field will be incremented for breaking changes
- Migration tools may be provided where practical

After v1.0, the format will follow semantic versioning for compatibility guarantees.
