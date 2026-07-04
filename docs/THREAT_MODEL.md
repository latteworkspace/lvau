# Threat Model

This document describes what Lvau protects against, what it does not, and the assumptions it makes. Read this before relying on Lvau for anything important.

## What Lvau is

Lvau is a **local encrypted capsule toolkit**. It encrypts individual files or entire directories into a `.lvau` envelope (capsule) using a password or keypair.

## What Lvau protects

### At-rest file confidentiality

If someone gains access to your encrypted `.lvau` files — for example, a stolen USB drive, a leaked backup, or an exposed cloud storage folder — they cannot read the file contents without the correct password (or private key).

### Envelope integrity

The AEAD construction (XChaCha20-Poly1305) authenticates both the ciphertext and the envelope header via additional authenticated data (AAD). If anyone modifies the encrypted file, decryption will fail with an authentication error.

### Password brute-force resistance

Lvau uses Argon2id as its key derivation function with configurable cost parameters. The default `balanced` profile uses 64 MB of memory and 2 iterations, making brute-force attacks significantly more expensive than simple hash-based KDFs.

### Bundle manifest integrity

When using bundle mode, the private manifest (file paths, sizes, per-file hashes) is encrypted and authenticated alongside the payload. Tampering with the manifest is detected during extraction.

### Signed provenance (optional)

When an `.lvau` file is signed with Ed25519, the signature covers the public envelope and all ciphertext bytes. This provides:

- **Author attribution**: Verify who created the encrypted artifact.
- **Tamper evidence**: Any modification to the envelope or ciphertext invalidates the signature.
- **No decryption required**: Verification works without knowing the decryption password or private key.

> **Important**: Ed25519 signatures and AEAD authentication serve different purposes. AEAD authentication (Poly1305) proves that the ciphertext was not modified *since encryption*. Ed25519 signatures prove *who created* the artifact. AEAD alone does not prove authorship.

### Capsule Policy Enforcement (Optional)

When a `.lvau` file is created or verified with a `CapsulePolicy`, Lvau enforces rules such as required cryptographic algorithms, KDF memory costs, and mandatory signatures. This helps organizations ensure all their encrypted capsules meet minimum security standards before they are trusted.

## What Lvau does NOT protect

### File metadata

Lvau does **not** encrypt or hide:

- File names
- File sizes (the `.lvau` file size reveals the approximate plaintext size)
- File timestamps (creation, modification, access times)
- File system permissions
- Directory structure

An attacker who sees your encrypted files can tell how many files you have, how large they are, and when they were last modified.

**Bundle mode note**: By default, bundle mode does not expose internal file names or directory structure in the public inspect output. The private manifest containing file paths is encrypted. However, the total encrypted payload size is visible, and approximate file counts may be inferred from the payload size. Use `--pad bucket` or `--pad fixed:<SIZE>` to reduce size-based inference.

### Weak passwords

If you choose a weak password (e.g., `password123`, `1234`, a dictionary word), Argon2id cannot save you. The KDF slows down brute-force attempts, but a weak password will eventually be found.

**Recommendation:** Use a strong, unique passphrase of at least 4-5 random words, or a password manager-generated password of 16+ characters.

### Local malware

If your machine is compromised with malware that can:

- Read process memory
- Log keystrokes
- Intercept file I/O

Then Lvau cannot protect your data. The password and plaintext will be visible to the malware during encryption or decryption.

Lvau zeroizes key material from memory after use where practical, but this is a best-effort defense, not a guarantee against a compromised operating system.

### Memory compromise

An attacker with access to your system's memory (via cold boot attacks, DMA attacks, or memory forensics) may be able to extract key material while Lvau is running or shortly after. Lvau uses the `zeroize` crate to clear secrets, but:

- The Rust compiler or OS may create copies
- Swap files may contain residual key material
- Core dumps may capture secrets

### Network attacks

Lvau is a local tool. It does not transmit data over the network. If you share `.lvau` files via insecure channels, the channel security is your responsibility — but the file contents remain encrypted.

### Side-channel attacks

Lvau does not make specific claims about resistance to timing attacks, cache attacks, or power analysis. The underlying Rust crypto libraries (`chacha20poly1305`, `aes-gcm`, `argon2`) aim for constant-time implementations, but Lvau does not independently verify this.

### Multiple-device key synchronization

Lvau does not manage keys across devices. If you use keypair encryption, keeping your private key synchronized and secure across machines is your responsibility.

### Bundle extraction in hostile environments

Bundle extraction includes safety checks (path traversal, absolute paths, symlinks), but Lvau does not:

- Protect against time-of-check/time-of-use (TOCTOU) races on the filesystem
- Guarantee atomicity of multi-file extraction
- Provide secure deletion of extracted plaintext files

## Assumptions

### Password-based encryption

- The user chooses a strong password
- The password is entered via a hidden prompt (CLI) or masked field (GUI), not passed as a command-line argument
- The password is not stored on disk
- The KDF parameters are appropriate for the user's threat model

### Operating system trust

- The OS kernel is not compromised
- The random number generator (`OsRng`) provides cryptographically secure random bytes
- The filesystem writes are durable (data reaches disk)

### Cryptographic library trust

Lvau relies on the following Rust crates for cryptographic operations:

| Operation | Crate | Algorithm |
|-----------|-------|-----------|
| Symmetric encryption | `chacha20poly1305` | XChaCha20-Poly1305 |
| Symmetric encryption (cascade) | `aes-gcm` | AES-256-GCM |
| Key derivation | `argon2` | Argon2id v0x13 |
| Key expansion | `hkdf` | HKDF-SHA256 |
| Hashing | `sha2` | SHA-256 |
| File hashing (bundles) | `blake3` | BLAKE3 |
| Key exchange | `x25519-dalek` | X25519 |
| Post-quantum KEM | `ml-kem` | ML-KEM-768 |
| Signatures | `ed25519-dalek` | Ed25519 |

These are widely-used, community-reviewed crates. Lvau does not implement any cryptographic primitives from scratch.

### Signing trust model

- Ed25519 signatures prove that someone holding the signing private key created the artifact.
- Lvau does not provide a certificate authority, key directory, or trust chain.
- Users must verify signing public keys through out-of-band channels (e.g., checking a project README, receiving the key in person, or verifying a fingerprint).
- Signing is optional and never required by default.

## Recovery expectations

### Lost password

If you lose your password and haven't set up offline recovery shares, **your data is unrecoverable**. There is no master key backdoor.

Lvau supports **Shamir Secret Sharing** (`lvau-cli recovery split`) to split a keypair or master key into offline recovery shares, allowing reconstruction if the primary password is lost. Without this explicit setup, recovery is impossible.

### Corrupted files

If a `.lvau` file is corrupted (even a single bit flip), decryption will fail with an authentication error. Lvau does not include error correction in the default envelope format.

**Recommendation:** Keep backups of both your original files and your encrypted files.

### Backups

Lvau does not manage backups. You are responsible for:

- Backing up your original files before encrypting
- Backing up your `.lvau` files
- Backing up your keypair files (`.lvau-key`, `.lvau-pub`) if using keypair encryption
- Backing up your signing keys (`.lvau-sign`, `.lvau-verify`) if using signatures
- Storing backups in a separate location

### Rekeying and Recipient Modification (Deferred to v0.4.0)

In v0.3.0, it is not possible to safely modify an existing `.lvau` capsule in place to add or remove recipients, or to re-key it without decrypting and re-encrypting the payload. Multi-recipient encryption is fully supported when creating new hybrid keypair capsules, but subsequent modification is deferred to v0.4.0 to ensure cryptographic integrity. If you need to change passwords or recipients, you must decrypt the file and create a new `.lvau` capsule.

## Recommended usage

- Encrypting personal files before uploading to cloud storage
- Encrypting backups at rest
- Encrypting sensitive documents on a shared machine
- File-level encryption in scripts or automation
- Bundling project secrets into a single encrypted artifact
- Signing release artifacts for integrity verification

## Unsafe usage

- Protecting against a compromised operating system
- Hiding the existence of encrypted files (Lvau is not a steganography tool)
- Replacing full-disk encryption
- Protecting data in transit (use TLS or similar)
- Storing passwords or key material alongside encrypted files

## Audit status

Lvau has **not been formally audited** by a third-party security firm.

The cryptographic design uses standard, well-reviewed primitives and well-maintained Rust crates. However, the integration, envelope construction, and key management code have not been professionally reviewed.

**A formal audit is a goal for future releases.** If you are a security researcher and want to review Lvau, we welcome your feedback — see [SECURITY.md](../SECURITY.md).

## Note on the LCO layer

The `Extreme` security profile includes an additional obfuscation layer called LCO (Lvau Custom Obfuscator). This is a keyed byte permutation applied on top of the standard AEAD encryption.

**LCO is explicitly NOT a cryptographic security boundary.** All security guarantees come from the standard AEAD layers (XChaCha20-Poly1305 and AES-256-GCM). LCO provides only defense-in-depth obfuscation and should not be relied upon for confidentiality.
