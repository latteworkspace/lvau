# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-07-04

### Added
- **Capsule Policy**: Enforce strict linting rules on `.lvau` capsules before creation or at inspection time via `CapsulePolicy` TOML specification.
- **Preflight Verification**: Safely audit `.lvau` capsules without decryption keys, generating detailed human-readable or JSON reports via `lvau-cli preflight`.
- **Approval Seals**: Support appending Ed25519 co-signatures to the envelope's public metadata (AAD) without modifying or decrypting the payload, via `lvau-cli approve`.
- **Encrypted Manifest Diffing**: Decrypt and compare the `BundleManifest` of two directory bundles to generate `Added/Removed/Modified/Unchanged` reports via `lvau-cli bundle diff`.
- **Verification Reporting**: Full static and dynamic verification reports via `lvau-cli report`.

### Changed
- Differentiated Lvau as an "encrypted capsule toolkit" prioritizing inspectability, policy compliance, and safe developer workflows.
- Extensively modified `lvau-protocol` to support `approvals`, `content_type`, `signature`, `public_label`, `release_metadata`, `policy_overridden`, and `recovery_metadata`.

## [0.2.0] - 2026-07-03

### Added

- **Sealed Bundle Mode**: `lvau-cli bundle pack` encrypts a directory into a single `.lvau` file, hiding file names, sizes, and structure in an encrypted manifest.
- **Bundle Manifest**: Cryptographically binds relative paths, file sizes, and BLAKE3 hashes to the payload.
- **Security Profile Check**: Verifies that the capsule's profile satisfies the minimum required security level (e.g., `Paranoid`).
- **Memory Hardness Warnings**: Warns if the KDF memory cost is suspiciously low or zero.
- **Public Label**: Optional plaintext label visible during inspection (e.g., for routing or CI tagging).

### Fixed

- Path traversal vulnerabilities during bundle extraction (`..` or absolute paths are rejected).
- Clippy warnings and Rust formatting inconsistencies.

## [0.1.0] - 2026-07-01

Initial public release preparation.

### Added

- **CLI** (`lvau-cli`): encrypt, decrypt, inspect, and keygen commands
- **GUI** (`lvau-gui`): cross-platform native GUI with password and keypair support
- **Encryption**: XChaCha20-Poly1305 AEAD as default algorithm
- **KDF**: Argon2id with configurable security profiles (fast, balanced, archive, paranoid)
- **Key separation**: HKDF-SHA256 for deriving independent encryption keys from master key
- **Versioned envelope**: `.lvau` format with magic bytes, version field, and AAD-bound metadata
- **Metadata inspection**: read envelope metadata without decrypting content
- **Truncation detection**: envelope stores plaintext length and rejects mismatched decrypt output
- **CLI overwrite safety**: output files are not replaced unless `--force` is supplied
- **CLI automation**: `--password-file` and `--seed-file` support non-interactive local workflows
- **Parallel encryption**: 1 MB chunked processing via Rayon
- **Hybrid keypair**: X25519 + ML-KEM-768 key exchange (experimental)
- **Cascade encryption**: AES-256-GCM + XChaCha20-Poly1305 cascade in paranoid profile
- **Self-extracting archives**: SFX `.exe` output via `lvau-stub`
- **Zeroized secrets**: key material cleared from memory after use
- **CI**: GitHub Actions for fmt, clippy, test, build
- **Release workflow**: cross-platform binary builds (Linux, Windows, macOS)
- **Security audit**: weekly `cargo audit` via GitHub Actions
- **Documentation**: threat model, format specification, security policy, contributing guide

### Security

- This release has **not been formally audited**
- The `.lvau` format is **not yet stable** and may change before v1.0
- Hybrid keypair encryption, cascade profiles, GUI, and SFX remain experimental
