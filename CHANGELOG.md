# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.3.0] - Unreleased

### Added
- **Sealed bundle mode**: New `lvau-cli bundle` subcommand with `pack`, `extract`, `inspect`, `list`, and `verify` sub-commands. Packs a directory into a single encrypted `.lvau` file with an authenticated private manifest.
- **Signed provenance**: New `lvau-cli sign-keygen`, `sign`, and `verify-signature` commands using Ed25519 signatures. Verify authorship without the decryption password.
- **`--json` output**: Machine-readable JSON output for `inspect` and `verify` commands.
- **Bundle safety**: Path traversal rejection (absolute paths, `..`, Windows drive paths, symlinks) on extraction. `--dry-run` mode for previewing extraction without writing files.
- **Metadata privacy**: `--metadata-profile` (`minimal`, `balanced`, `verbose`) and `--pad` (`none`, `bucket`, `fixed:<SIZE>`) options for bundle mode.
- **Documentation overhaul**: "What makes Lvau different?" section, comparison table (age, VeraCrypt, Cryptomator, SOPS), honest security disclaimers, weak password guidance, roadmap.
- **Hardened tests**: Property roundtrip tests, corrupt magic/version tests, additional wrong-password/wrong-key tests, path traversal rejection tests, bundle roundtrip tests, signature verification tests.
- **ContentType envelope field**: New `content_type` field distinguishes single-file and bundle payloads. Legacy files (v0.2.x) default to single-file mode.
- **EnvelopeSignature**: Optional signature block in the envelope for signed artifacts.
- **docs/ROADMAP.md**: Version roadmap for v0.3.0, v0.4.0, and v1.0.

### Changed
- Updated README.md and README_ja.md with new feature documentation and honest positioning.
- Updated docs/THREAT_MODEL.md with bundle, signature, and metadata privacy considerations.
- Updated docs/FORMAT.md with new envelope fields and backward compatibility notes.

### Security
- This release has **not been formally audited**.
- The `.lvau` format is **not yet stable** and may change before v1.0.
- Hybrid keypair encryption, cascade profiles, GUI, and SFX remain experimental.
- Bundle extraction rejects path traversal, absolute paths, and symlinks by default.
- Signed provenance uses Ed25519; signatures cover the envelope and ciphertext.

## [0.2.1] - Unreleased

### Added
- **Verification**: New `lvau-cli verify` command to safely verify ciphertext integrity without persisting plaintext to disk.
- **Diagnostics**: New `lvau-cli self-test` and `lvau-cli doctor` commands.
- **Documentation**: Corrected outdated references to memory limits and format specifications.

## [0.2.0] - 2026-07-02

### Added
- **Streaming processing**: Files are no longer read entirely into memory. They are processed in 1 MiB chunks.
- **Windows ACLs**: Private key files are securely restricted to the owner using `SetNamedSecurityInfoW`.
- **Global Chunk Indexing**: The 64-bit chunk index is now included in the AAD to prevent chunk swapping or reordering.
- **Upgraded FEK wrapping**: Password-derived Key Wrapping Key (KWK) now uses XChaCha20-Poly1305 instead of AES-GCM.

### Fixed
- Nonce usage in the hybrid key wrapper.
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
