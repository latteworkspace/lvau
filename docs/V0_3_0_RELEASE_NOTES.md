# Lvau v0.3.0 Release Notes

We are thrilled to announce **Lvau v0.3.0**, a major update that brings sealed directory bundles, cryptographic signatures, JSON automation support, and significant improvements to our security baseline and documentation.

## What's New

### 1. Sealed Directory Bundles (`lvau-cli bundle`)
You can now securely encrypt entire directories into a single `.lvau` file without exposing file names or directory structures.
- Use `lvau-cli bundle pack` to encrypt a directory.
- Use `lvau-cli bundle extract` to decrypt it safely.
- Directory traversal and symlink extraction are blocked by default for maximum security.

### 2. Ed25519 Signatures (`lvau-cli sign`)
Ensure the authenticity of your encrypted files with Ed25519 signatures. Signatures cover both the public envelope and the ciphertext payload.
- Generate keys with `lvau-cli sign-keygen`.
- Sign envelopes with `lvau-cli sign`.
- Verify signatures with `lvau-cli verify-signature` without needing the decryption password or private key.

### 3. Automation and Integration (`--json`)
Lvau is now easier to integrate into scripts and automated workflows. Use the `--json` flag with `inspect` and `verify` commands to output structured, machine-readable JSON data instead of human-readable text.

### 4. Security Hardening
- **Path Traversal Protection**: Enforced during bundle extraction.
- **Improved Validation**: Stricter envelope header validation to fail fast on corrupted magic bytes or version fields.
- **Comprehensive Testing**: Added extensive integration and unit tests covering edge cases like file truncation and tampered envelopes.

### 5. GUI Improvements
- Added an "Inspect" mode to easily view envelope metadata.
- Clear warning labels are now displayed when using experimental features like Cascade profiles or SFX.
- Explicit "Force Overwrite" checkbox added for safety.

### 6. Documentation Overhaul
- Updated our **Threat Model** and **Format Specification** to clearly delineate what Lvau protects against and how it compares to standard tools like age, VeraCrypt, and Cryptomator.
- Explicitly documented that Lvau uses standard cryptography and that `extreme` profile LCO is an obfuscation layer, not a cryptographic boundary.

## Migration Guide
- v0.3.0 retains reader compatibility with supported v0.2.x envelopes.
- However, v0.2.x cannot decrypt v0.3.0 bundle envelopes or recognize signature fields. We recommend all users upgrade to v0.3.0.

*Download the latest binaries below for Windows, macOS, and Linux.*
