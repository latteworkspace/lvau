# Threat Model

This document describes what Lvau protects against, what it does not, and the assumptions it makes. Read this before relying on Lvau for anything important.

## What Lvau is

Lvau is a **local file encryption toolkit**. It encrypts individual files on your machine using a password (or keypair) and writes a versioned `.lvau` envelope to disk.

## What Lvau protects

### At-rest file confidentiality

If someone gains access to your encrypted `.lvau` files — for example, a stolen USB drive, a leaked backup, or an exposed cloud storage folder — they cannot read the file contents without the correct password (or private key).

### Envelope integrity

The AEAD construction (XChaCha20-Poly1305) authenticates both the ciphertext and the envelope header via additional authenticated data (AAD). If anyone modifies the encrypted file, decryption will fail with an authentication error.

### Password brute-force resistance

Lvau uses Argon2id as its key derivation function with configurable cost parameters. The default `balanced` profile uses 64 MB of memory and 2 iterations, making brute-force attacks significantly more expensive than simple hash-based KDFs.

## What Lvau does NOT protect

### File metadata

Lvau does **not** encrypt or hide:

- File names
- File sizes (the `.lvau` file size reveals the approximate plaintext size)
- File timestamps (creation, modification, access times)
- File system permissions
- Directory structure

An attacker who sees your encrypted files can tell how many files you have, how large they are, and when they were last modified.

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
| Key exchange | `x25519-dalek` | X25519 |
| Post-quantum KEM | `ml-kem` | ML-KEM-768 |

These are widely-used, community-reviewed crates. Lvau does not implement any cryptographic primitives from scratch.

## Recovery expectations

### Lost password

If you lose your password, **your data is unrecoverable**. There is no master key, no recovery mechanism, and no backdoor. This is by design.

### Corrupted files

If a `.lvau` file is corrupted (even a single bit flip), decryption will fail with an authentication error. Lvau does not include error correction in the default envelope format.

**Recommendation:** Keep backups of both your original files and your encrypted files.

### Backups

Lvau does not manage backups. You are responsible for:

- Backing up your original files before encrypting
- Backing up your `.lvau` files
- Backing up your keypair files (`.lvau-key`, `.lvau-pub`) if using keypair encryption
- Storing backups in a separate location

## Recommended usage

- Encrypting personal files before uploading to cloud storage
- Encrypting backups at rest
- Encrypting sensitive documents on a shared machine
- File-level encryption in scripts or automation

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
