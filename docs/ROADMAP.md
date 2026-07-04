# Roadmap

This document outlines the planned releases for Lvau. Dates are estimates, not commitments.

## v0.3.0 — Inspectable, Signed, Sealed

**Theme**: Make Lvau clearly differentiated from age, VeraCrypt, Cryptomator, and SOPS.

### Implemented
- Sealed bundle mode (`lvau-cli bundle pack/extract/inspect/list/verify`)
- Ed25519 signed provenance (`lvau-cli sign-keygen/sign/verify-signature`)
- `--json` output for `inspect` and `verify`
- Hardened test suite (property roundtrips, corrupt envelopes, path traversal, symlinks)
- Documentation overhaul (comparison table, roadmap, honest positioning)
- Metadata privacy profiles for bundles (`--metadata-profile`)
- Size padding profiles for bundles (`--pad`)
- Bundle extraction safety (path traversal, absolute paths, symlinks, overwrite protection)
- `--dry-run` mode for bundle extraction

## v0.4.0 — Recovery and Multi-Recipient

**Theme**: Make encrypted data recoverable and shareable.

### Planned
- **Recovery shares**: Shamir Secret Sharing for private key recovery. Split a key into N shares with threshold T. `lvau-cli recovery split/combine/inspect`.
- **Rekey / Recipient slots**: Multiple recipients for a single encrypted file. Add or remove recipients without re-encrypting the payload. `lvau-cli rekey add-recipient/remove-recipient/list-recipients`.
- **Structured secret mode**: Lightweight developer-focused encrypted config files (.env, JSON, YAML, TOML). `lvau-cli secret encrypt/decrypt/edit/print --redact`.
- **Value-only encryption**: Optional per-value encryption within structured config files (placeholder in v0.3.0, implementation in v0.4.0).

### Design Notes
- Recovery shares protect private keys, not passwords.
- Rekey uses a random data encryption key with recipient-specific wrapping.
- Adding a recipient does not require re-encrypting the payload.
- Removing a recipient should warn that old copies remain decryptable.
- Structured secret mode does not need to match SOPS feature-for-feature.
- The `edit` command will use `$EDITOR` with a secure temporary file.

## v1.0 — Stable Format and Audit

**Theme**: Stability, trust, and production readiness.

### Goals
- **Format freeze**: The `.lvau` envelope format will be frozen at v1.0. Breaking format changes after v1.0 must increment the major version.
- **Formal audit**: Engage a third-party security firm to audit the cryptographic implementation, envelope parsing, and key management.
- **Stable API**: The `lvau-core` public API should be stable enough for library consumers.
- **SBOM**: Include a Software Bill of Materials in release assets.
- **Signed releases**: Sign release checksums with the project signing key.
- **Demo recordings**: Include terminal recordings or GIFs in documentation.

### Prerequisites
- All v0.3.0 and v0.4.0 features implemented and tested.
- No known cryptographic implementation issues.
- Comprehensive property-based test coverage.
- Clear upgrade path from v0.x files.

## Non-Goals

The following are explicitly not planned for Lvau:

- Full-disk encryption (use VeraCrypt)
- Cloud vault synchronization (use Cryptomator)
- Network protocol / TLS replacement
- Steganography
- Custom cipher invention as a security boundary
- Claims of "military-grade" or "unbreakable" security
- Formal verification of the Rust code (aspirational, but not a release blocker)
