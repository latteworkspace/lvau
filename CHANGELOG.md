# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-07-17

### Security

- New output uses envelope format v2, which AEAD-authenticates the declared plaintext length, nonces, recipient/KDF header, content type, public label, private metadata bytes, and policy-override marker. This closes keyless prefix-truncation and metadata-downgrade paths in format v1.
- Empty plaintext now emits an authenticated frame, and decryptors reject trailing ciphertext.
- Added bounded, exact envelope decoding plus recipient-count/type, wrapped-key length, nonce, and fixed Argon2id-profile validation before expensive allocation or KDF work.
- Author signatures now bind their stored fingerprint/comment, while v2 approval signatures bind the envelope, ciphertext, fingerprint, and comment. Trusting a signer remains an explicit caller decision.
- Bundle validation now checks canonical manifests, path safety, case-insensitive collisions, integer overflow, bounds, overlapping ranges, and every entry's BLAKE3 digest.
- Bundle packing rejects special files, and extraction refuses existing symlink/reparse-point or multi-hardlink targets even with `--force`.
- Recovery share v2 replaces the offline-guessable `SHA-256(secret)` identifier with a random set ID and replaces vulnerable `sharks` with the corrected `blahaj` implementation.
- Updated `crossbeam-epoch` to 0.9.20 for RUSTSEC-2026-0204, removed unused Postcard/Heapless default dependencies, and made `cargo-audit` 0.22.2 run from a validated, expiry-documented configuration.
- Private key, signing key, recovery share, and encrypted/decrypted output writes use restricted same-directory temporary files and fsync; Unix private outputs are mode `0600`.
- Unix password/seed files are rejected when group or other permission bits are present.

### Changed

- All workspace crates are versioned `0.4.0`; existing format-v1 and legacy v0.2 envelopes remain readable, while old binaries are not expected to read new format-v2 output.
- CLI prompts and diagnostics use stderr; JSON policy/preflight failures return a non-zero exit status and verify JSON is serialized safely.
- Common envelope parsing is shared by decrypt, inspect, policy, preflight, and bundle inspection paths.
- Legacy read compatibility is covered by a capsule fixture generated with the v0.3.0 release binary.
- Multi-recipient keypair decrypt/verify tries every compatible recipient slot rather than only the first.
- Bundle verification decrypts once instead of repeating the KDF and payload decryption.
- GUI cryptographic work now runs off the render thread, reports processed bytes, clears password/seed fields after dispatch, bounds its log buffer, and builds experimental SFX outputs by streaming into an atomic temporary file.
- CI uses locked dependencies, commit-pinned Actions, three-OS tests, tag/workspace/CHANGELOG validation, checksums, CycloneDX SBOMs, and GitHub artifact attestations.

### Fixed

- Empty `inspect` input and empty LCO nonces no longer panic.
- Failed encryption/decryption no longer leaves named temporary plaintext/output files behind.
- Signing-key fingerprints can no longer be spoofed by editing unsigned metadata.
- API-side fixed test-token authentication, pass-the-hash API-key lookup, cross-tenant recipient-group overwrite, empty-password encryption, blocking-job permit lifetime, Firebase fail-open configuration, and event-loop bcrypt work were fixed in the adjacent `lvau-api` repository.
- The adjacent website now enforces its Vercel-compatible 4 MB Lvau limit, rejects empty Lvau passwords, and accurately states that files and passwords transit the server-side proxy/API.

### Migration

- No CLI command or legacy read path is intentionally removed. To obtain v2 protections, decrypt an older capsule with a trusted Lvau version and re-encrypt it with 0.4.0; preserve and verify signatures separately because re-encryption creates a new artifact.
- Recovery share files remain decodable; newly generated share sets use version 2 identifiers.

## [0.3.0] - 2026-07-04

### Added
- **Capsule Policy**: Enforce strict linting rules on `.lvau` capsules before creation or at inspection time via `CapsulePolicy` TOML specification.
- **Preflight Verification**: Safely audit `.lvau` capsules without decryption keys, generating detailed human-readable or JSON reports via `lvau-cli preflight`.
- **Approval Seals**: Support appending Ed25519 co-signatures to the envelope's public metadata without decrypting the payload, via `lvau-cli approve`.
- **Encrypted Manifest Diffing**: Decrypt and compare the `BundleManifest` of two directory bundles to generate `Added/Removed/Modified/Unchanged` reports via `lvau-cli bundle diff`.
- **Verification Reporting**: Full static and dynamic verification reports via `lvau-cli report`.
- **Recipient Groups**: Encrypt files for a local group config of multiple hybrid public keys via `lvau-cli recipients group`.
- **Sealed Bundle Mode**: Full implementation of `bundle pack`, `extract`, `inspect`, `list`, and `verify` with dry-run capabilities and path traversal protections.
- **Signed Envelopes**: Optional Ed25519 signatures covering public envelope and ciphertext via `sign-keygen`, `sign`, and `verify-signature`.
- **Recovery Shares**: Split master keys into Shamir Secret Sharing (SSS) shares via `recovery split`, `combine`, and `inspect`.
- **Recipient Slots**: Support for wrapping one file-encryption key for multiple recipients at initial encryption time.
- **Structured Secret Mode**: Developer workflows for dotfiles via `secret encrypt`, `edit`, `decrypt`, and `print`.
- **Hardened Testing**: Comprehensive test suite including corrupt-envelope, truncated-file, path traversal, and wrong-password checks.

### Changed
- Differentiated Lvau as a "sealed encryption toolkit" prioritizing inspectability, recoverable artifacts, and safe developer workflows.
- Strengthened atomic writes and secret zeroization.

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
