# Threat Model

Lvau is built to protect local files and developer workflows from a variety of threats. This document details the attackers Lvau defends against, and the limitations of the tool.

## In Scope

Lvau is designed to protect against:

- **Data at Rest Compromise**: An attacker gaining access to a stolen laptop, backup drive, or cloud storage bucket will not be able to decrypt `.lvau` capsules without the password or private key.
- **Brute-force Attacks**: The use of Argon2id with high-memory profiles (`balanced`, `paranoid`) prevents attackers from efficiently parallelizing brute-force attacks on GPUs.
- **Unauthorized Modification**: The payload is authenticated using XChaCha20-Poly1305. A modified ciphertext will deterministically fail to decrypt. The public envelope uses an authenticated hash to prevent attackers from swapping KDF parameters or recipient slots unnoticed.
- **Impersonation**: With author signatures (`lvau-cli sign`), a recipient can mathematically verify the exact identity of the author before decrypting the capsule.

## Out of Scope

Lvau is **not** designed to protect against:

- **Endpoint Compromise**: If an attacker has root access or malware running on your machine while you decrypt a capsule, they can steal the plaintext or capture your password via a keylogger.
- **Side-Channel Attacks**: The GUI and CLI make a best-effort attempt to zeroize memory using the `zeroize` crate, but Rust cannot guarantee complete memory sanitization across the entire OS stack (e.g., swap files, CPU caches).
- **Plausible Deniability**: Lvau does not support hidden volumes or plausible deniability. A `.lvau` file is explicitly identifiable as an encrypted capsule.
- **Quantum Computing**: The symmetric payload (XChaCha20) is quantum-resistant. However, the author signatures (Ed25519) are not. The experimental hybrid keypair system uses ML-KEM-768 for post-quantum key encapsulation, but this implementation is **experimental** and should not be relied upon for critical infrastructure.

## Cryptographic Primitives

Lvau relies exclusively on standard, well-reviewed primitives:
- **XChaCha20-Poly1305**: Authenticated symmetric encryption.
- **Argon2id**: Memory-hard password hashing.
- **HKDF-SHA256**: Key derivation.
- **Ed25519**: Digital signatures.
- **X25519**: Elliptic-curve Diffie-Hellman.
- **ML-KEM-768**: Post-quantum key encapsulation (Experimental).
