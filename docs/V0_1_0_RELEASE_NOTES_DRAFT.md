# v0.1.0 — Boring, inspectable file encryption

Lvau is a file encryption toolkit built in Rust around standard cryptographic primitives and a versioned `.lvau` envelope format.

This is the first public release.

## What Lvau does

- Encrypts and decrypts individual files with a password or hybrid keypair
- Uses **XChaCha20-Poly1305** (AEAD) as the default encryption algorithm
- Derives keys from passwords using **Argon2id** with configurable cost profiles
- Separates keys via **HKDF-SHA256**
- Writes a versioned `.lvau` envelope that can be inspected without decrypting the payload
- Processes large files in parallel 1 MB chunks

## What works

- `lvau-cli`: command-line interface for encrypt, decrypt, inspect, and keypair generation
- `lvau-gui`: cross-platform native GUI (egui)
- Security profiles: `fast`, `balanced`, `archive`, `paranoid`
- Hybrid keypair encryption: X25519 + ML-KEM-768 (experimental)
- Self-extracting archives (Windows SFX)
- 4 automated tests: roundtrip, wrong password, tampered ciphertext, cascade with seed

## What is experimental

- **Hybrid keypair encryption** (X25519 + ML-KEM-768): uses standard implementations but the integration has not been widely reviewed
- **Cascade encryption profiles** (`paranoid`, `extreme`): additional cipher layers provide defense-in-depth but add complexity
- **`.lvau` format**: not yet stable — may change before v1.0

## Known limitations

- No streaming encryption — entire file is read into memory
- No file metadata encryption (filenames, sizes, timestamps are visible)
- No error correction in the envelope format
- No formal security audit has been performed
- The LCO layer in the `extreme` profile is a custom obfuscation — **not a cryptographic security boundary**
- All crates are currently `publish = false` (not on crates.io)

## Install

### Pre-built binaries

Download from the [GitHub Releases](https://github.com/lasder-ca/lvau/releases/tag/v0.1.0) page.

Available for:
- Linux x86_64
- Windows x86_64
- macOS x86_64
- macOS ARM (aarch64)

### From source

```sh
git clone https://github.com/lasder-ca/lvau.git
cd lvau
git checkout v0.1.0
cargo build --release
```

## Checksums

SHA-256 checksums for all release binaries are provided in `checksums.txt` in the release assets. Verify your download:

```sh
# Linux/macOS
sha256sum -c checksums.txt

# Windows (PowerShell)
Get-FileHash lvau-cli.exe -Algorithm SHA256
```

## Security disclaimer

Lvau has **not been formally audited**. It uses standard, well-reviewed cryptographic primitives via established Rust crates (`chacha20poly1305`, `aes-gcm`, `argon2`, `hkdf`), but the integration and envelope construction have not been professionally reviewed.

Use Lvau with that understanding. For the full threat model, see [docs/THREAT_MODEL.md](https://github.com/lasder-ca/lvau/blob/main/docs/THREAT_MODEL.md).

Report security issues responsibly — see [SECURITY.md](https://github.com/lasder-ca/lvau/blob/main/SECURITY.md).
