# Lvau

> Boring, inspectable file encryption for Rust apps and power users.

Lvau is a secure-by-default file encryption toolkit built around standard cryptographic primitives and a versioned `.lvau` envelope.

It focuses on simple local file encryption, inspectable metadata, stable formats, and a clean CLI/GUI experience.

English | [日本語 (Japanese)](README_ja.md)

[![CI](https://github.com/lasder-ca/lvau/actions/workflows/ci.yml/badge.svg)](https://github.com/lasder-ca/lvau/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Rust](https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=white)

---

## Quick demo

```sh
# Encrypt a file
lvau-cli encrypt --in-file secret.txt --out-file secret.lvau --password

# Inspect envelope metadata (no decryption needed)
lvau-cli inspect --in-file secret.lvau

# Decrypt
lvau-cli decrypt --in-file secret.lvau --out-file secret.txt --password
```

<!-- TODO: Add screenshot or demo GIF here -->

---

## Features

- **XChaCha20-Poly1305 AEAD** — default encryption with 192-bit random nonce per file
- **Argon2id KDF** — password-based key derivation with configurable cost profiles
- **HKDF key separation** — master key expanded into independent encryption keys
- **Versioned `.lvau` envelope** — inspectable metadata bound via AEAD additional authenticated data (AAD)
- **Parallel chunked encryption** — 1 MB chunks processed in parallel via Rayon
- **Zeroized secrets** — sensitive key material cleared from memory after use
- **Security profiles** — `fast`, `balanced`, `archive`, `paranoid` presets for Argon2id cost tuning
- **CLI-first** — clean command-line interface via `clap`
- **GUI available** — cross-platform native GUI via `egui`
- **Hybrid keypair encryption** — X25519 + ML-KEM-768 for post-quantum key exchange (experimental)
- **Self-extracting archives** — optional SFX `.exe` output (Windows)

---

## Install

### From release binaries

Download the latest binary for your platform from [GitHub Releases](https://github.com/lasder-ca/lvau/releases).

| Platform | Binary |
|----------|--------|
| Linux x86_64 | `lvau-cli-x86_64-unknown-linux-gnu.tar.gz` |
| Windows x86_64 | `lvau-cli-x86_64-pc-windows-msvc.zip` |
| macOS x86_64 | `lvau-cli-x86_64-apple-darwin.tar.gz` |
| macOS ARM | `lvau-cli-aarch64-apple-darwin.tar.gz` |

Verify checksums against `checksums.txt` in the release.

### From source

Requires [Rust and Cargo](https://rustup.rs/).

```sh
git clone https://github.com/lasder-ca/lvau.git
cd lvau
cargo build --release
```

Binaries will be in `target/release/`:
- `lvau-cli` (or `lvau-cli.exe` on Windows)
- `lvau-gui` (or `lvau-gui.exe` on Windows)

---

## Quick start

### Encrypt a file with a password

```sh
lvau-cli encrypt --in-file document.pdf --out-file document.pdf.lvau --password
# You will be prompted to enter and confirm a password
```

### Decrypt

```sh
lvau-cli decrypt --in-file document.pdf.lvau --out-file document.pdf --password
# Enter the same password used for encryption
```

### Inspect an encrypted file

View envelope metadata without decrypting:

```sh
lvau-cli inspect --in-file document.pdf.lvau
```

### Choose a security profile

Profiles control the Argon2id cost parameters:

```sh
lvau-cli encrypt --in-file data.bin --out-file data.bin.lvau --password --profile archive
```

| Profile | Argon2id memory | Use case |
|---------|----------------|----------|
| `fast` | 16 MB | Quick operations, testing |
| `balanced` | 64 MB | Default — general use |
| `archive` | 256 MB | Long-term storage |
| `paranoid` | 1 GB | High-security archives |

---

## Why Lvau?

Lvau exists because we wanted a simple, local file encryption tool that:

1. **Uses standard, boring cryptography** — no custom ciphers as a security boundary
2. **Has an inspectable format** — you can read the envelope metadata without decrypting
3. **Ships safe defaults** — strong KDF parameters out of the box
4. **Is a single binary** — no runtime dependencies, no configuration files
5. **Has a clear threat model** — we document what it protects and what it doesn't

Lvau is not trying to replace `age`, VeraCrypt, Cryptomator, or `rclone crypt`. Each tool has different strengths. See the [comparison table](#comparison) below.

---

## Security model

Lvau is designed for **local file encryption with a password** (or keypair).

**What it protects:**
- File contents at rest on disk
- Envelope metadata integrity via AEAD

**What it does NOT protect:**
- File names, sizes, or filesystem metadata
- Against local malware with memory access
- Against weak passwords
- Against key compromise

Lvau has **not been formally audited**. Use it with that understanding.

For the full threat model, see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

---

## File format

Lvau files use a versioned binary envelope serialized with [postcard](https://crates.io/crates/postcard):

```
┌──────────────────────────────────────┐
│ Magic bytes: "LVAU" (4 bytes)        │
│ Version: u16 (currently 1)           │
│ Header:                              │
│   ├─ Security profile                │
│   ├─ Algorithm ID                    │
│   ├─ KDF params (Argon2id salt/cost) │
│   └─ Recipients                      │
│ Nonce: 24 bytes                      │
│ Secondary nonce: 12 bytes (optional) │
│ AAD hash: SHA-256 of header (32 B)   │
│ Ciphertext: AEAD-encrypted payload   │
│ Metadata: (reserved, currently empty)│
└──────────────────────────────────────┘
```

The format is **not yet stable before v1.0**. See [docs/FORMAT.md](docs/FORMAT.md) for full documentation.

---

## CLI usage

```
lvau-cli <COMMAND> [OPTIONS]

Commands:
  encrypt   Encrypt a file
  decrypt   Decrypt a file
  inspect   Inspect an encrypted file's metadata
  keygen    Generate a hybrid keypair (X25519 + ML-KEM-768)
```

### Encrypt

```sh
# Password-based (default profile: balanced)
lvau-cli encrypt --in-file input.txt --out-file output.lvau --password

# With a specific security profile
lvau-cli encrypt --in-file input.txt --out-file output.lvau --password --profile paranoid

# With an additional seed (pepper)
lvau-cli encrypt --in-file input.txt --out-file output.lvau --password --seed

# Keypair-based encryption
lvau-cli encrypt --in-file input.txt --out-file output.lvau --pub-key recipient.lvau-pub

# Create a self-extracting archive (Windows)
lvau-cli encrypt --in-file input.txt --out-file output.exe --password --sfx
```

### Decrypt

```sh
# Password-based
lvau-cli decrypt --in-file output.lvau --out-file input.txt --password

# Keypair-based
lvau-cli decrypt --in-file output.lvau --out-file input.txt --priv-key my.lvau-key
```

### Inspect

```sh
lvau-cli inspect --in-file output.lvau
```

### Keygen

```sh
lvau-cli keygen --out-base my-identity
# Creates: my-identity.lvau-key (private) and my-identity.lvau-pub (public)
```

### Verbose mode

Add `-v` or `--verbose` to any command for debug logging:

```sh
lvau-cli encrypt --in-file input.txt --out-file output.lvau --password -v
```

---

## GUI

Lvau includes a cross-platform native GUI (`lvau-gui`) built with [egui](https://github.com/emilk/egui).

The GUI supports:
- File selection via dialog
- Password or keypair authentication
- Security profile selection
- Self-extracting archive (SFX) creation
- Real-time operation logs

Run it:

```sh
cargo run --release --package lvau-gui
# or use the built binary:
./target/release/lvau-gui
```

---

## Project status

**v0.1.0 — Experimental**

Lvau is in early development. It is functional and tested, but:

- The `.lvau` format is **not yet stable** and may change before v1.0
- The project has **not been formally audited**
- The hybrid keypair (X25519 + ML-KEM-768) support is **experimental**
- API surface may change

Use Lvau for personal projects and experimentation. For production use with sensitive data, consider established tools like [age](https://age-encryption.org/) until Lvau has been more widely reviewed.

---

## Comparison

<a id="comparison"></a>

| Tool | Main use | Lvau difference |
|------|----------|-----------------|
| [age](https://age-encryption.org/) | Excellent file encryption | Lvau focuses on password-based local encryption, GUI support, and inspectable versioned envelopes |
| [Cryptomator](https://cryptomator.org/) | Cloud folder encryption | Lvau focuses on file/archive workflows and Rust integration |
| [VeraCrypt](https://veracrypt.fr/) | Encrypted volumes | Lvau is lighter and file-oriented |
| [rclone crypt](https://rclone.org/crypt/) | Cloud sync encryption | Lvau is local-first and format-focused |

Lvau does not claim to be more secure than any of these tools. They are all excellent. Choose the one that fits your use case.

---

## Architecture

Lvau is modularized into independent crates:

```
lvau-cli ──→ lvau-core ──→ lvau-protocol
lvau-gui ──→ lvau-core
lvau-stub ──→ lvau-core
```

| Crate | Purpose |
|-------|---------|
| `lvau-protocol` | Envelope format definitions and serialization (postcard) |
| `lvau-core` | Crypto engine — Argon2id, HKDF, XChaCha20-Poly1305, key management |
| `lvau-cli` | Command-line interface (clap) |
| `lvau-gui` | Native GUI (egui) |
| `lvau-stub` | SFX self-extracting archive stub |

---

## Development transparency

This project uses AI tools (such as Gemini) to assist with code generation and review. All AI-generated output is reviewed, tested, and corrected by humans. The cryptographic design relies on standard, well-reviewed primitives — not on AI-generated algorithms.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for build instructions, testing, and contribution guidelines.

Security-sensitive contributions have additional requirements — please read the guide before submitting crypto-related changes.

---

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">

If Lvau is useful to you or you want to follow development, a ⭐ helps the project grow.

</div>
