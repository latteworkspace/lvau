# Lvau

> Boring, inspectable file encryption for Rust apps and power users.

Lvau is a Rust-based local file encryption toolkit. It uses standard cryptographic primitives, safe defaults, and a versioned `.lvau` envelope that can be inspected without decrypting the payload.

English | [Japanese](README_ja.md)

[![CI](https://github.com/lasder-ca/lvau/actions/workflows/ci.yml/badge.svg)](https://github.com/lasder-ca/lvau/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> **⚠️ Not audited.** Lvau has not been formally audited by a third-party security firm. See [SECURITY.md](SECURITY.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Quick Demo

```sh
lvau-cli encrypt --in-file secret.txt --out-file secret.txt.lvau --password
lvau-cli inspect --in-file secret.txt.lvau
lvau-cli decrypt --in-file secret.txt.lvau --out-file secret.restored.txt --password
```

For automated scripts and tests, use a local password file instead of putting a password in shell history:

```sh
lvau-cli encrypt --in-file secret.txt --out-file secret.txt.lvau --password-file password.txt
```

## What Makes Lvau Different?

Lvau is not trying to replace age, VeraCrypt, Cryptomator, or SOPS. Each tool excels at a specific use case. Lvau focuses on a different combination:

1. **Inspectable envelope** — Every `.lvau` file has a public header you can read without the password. You can verify the format version, algorithm, KDF parameters, and recipient type before you decrypt.
2. **Sealed bundles** — Pack an entire directory into a single encrypted `.lvau` file with an authenticated private manifest. Metadata privacy is configurable.
3. **Signed provenance** — Optionally sign encrypted artifacts with Ed25519. Verify authorship without knowing the decryption password.
4. **CLI-first automation** — Every feature works from scripts, CI pipelines, and cron jobs. `--password-file`, `--json` output, and `--dry-run` modes are first-class.
5. **Safe defaults** — Refuses overwrite without `--force`. Rejects path traversal on extraction. Atomic writes via temp+rename. Zeroized key material.
6. **Boring cryptography** — XChaCha20-Poly1305 AEAD, Argon2id KDF, HKDF-SHA256. No custom ciphers as security boundaries.

### Comparison

| Feature | Lvau | age | VeraCrypt | Cryptomator | SOPS |
| --- | :---: | :---: | :---: | :---: | :---: |
| File encryption | ✅ | ✅ | — | — | — |
| Directory bundles | ✅ | — | — | ✅ | — |
| Disk/container encryption | — | — | ✅ | — | — |
| Cloud vault sync | — | — | — | ✅ | — |
| Structured secrets (JSON/YAML) | planned | — | — | — | ✅ |
| Inspectable envelope | ✅ | — | — | — | — |
| Signed artifacts | ✅ | — | — | — | ✅ |
| CLI automation | ✅ | ✅ | limited | — | ✅ |
| GUI | ✅ | — | ✅ | ✅ | — |
| Post-quantum hybrid (experimental) | ✅ | — | — | — | — |
| Formally audited | **no** | **yes** | **yes** | **yes** | varies |
| Rust implementation | ✅ | ✅ (Go) | C++ | Java | Go |

**Honest assessment:**
- **age** is excellent for simple, audited file encryption. If you need nothing else, use age.
- **VeraCrypt** is excellent for full-disk and container encryption.
- **Cryptomator** is excellent for transparent cloud-synced vaults.
- **SOPS** is excellent for structured secret management in GitOps workflows.
- **Lvau** focuses on inspectable envelopes, signed encrypted artifacts, sealed directory bundles, recovery workflows, and CLI-first local developer workflows.

## Features

- XChaCha20-Poly1305 AEAD for the default password encryption path.
- Argon2id password KDF with `fast`, `balanced`, `archive`, `paranoid`, and `extreme` profiles.
- HKDF-SHA256 key separation.
- Versioned `.lvau` envelope with magic bytes, version, public KDF metadata, nonces, authenticated header hash, and plaintext length.
- Parallel 1 MiB chunk encryption via Rayon.
- Hidden password prompts in the CLI, plus `--password-file` for non-interactive automation.
- Refuses to overwrite output unless `--force` is provided.
- Atomic output writes (write to temp file, fsync, rename).
- `--json` output for inspect and verify commands.
- Native GUI via `egui`.

### New in v0.3.0

- **Sealed bundle mode** — Pack a directory into one encrypted `.lvau` file with an authenticated manifest. Configurable metadata privacy and size padding.
- **Signed provenance** — Sign encrypted artifacts with Ed25519. Verify authorship without the decryption password.
- **Hardened tests** — Property roundtrip tests, corrupt envelope tests, path traversal tests, and more.
- **`--json` output** — Machine-readable output for inspect and verify.

## Experimental Features

These are available, but should be treated as experimental in v0.3.0:

- Hybrid keypair encryption using X25519 + ML-KEM-768.
- Cascade profiles (`paranoid`, `extreme`).
- The LCO layer used by `extreme`. LCO is an obfuscation layer, not a cryptographic security boundary.
- Windows self-extracting archives (`--sfx`).

## Security Warnings

> **⚠️ Do not use weak passwords.** Argon2id slows brute-force attacks, but cannot protect passwords like `password123` or `1234`. Use a strong, unique passphrase of at least 4–5 random words, or a password manager-generated password of 16+ characters.

> **⚠️ Not audited.** The cryptographic design uses standard, well-reviewed primitives, but the implementation has not been professionally reviewed. For sensitive production use, also evaluate age, VeraCrypt, Cryptomator, or similar audited tools.

## Install

### Release Binaries

Download archives from [GitHub Releases](https://github.com/lasder-ca/lvau/releases).

| Platform | Asset |
| --- | --- |
| Linux x86_64 | `lvau-x86_64-unknown-linux-gnu.tar.gz` |
| Windows x86_64 | `lvau-x86_64-pc-windows-msvc.zip` |
| macOS x86_64 | `lvau-x86_64-apple-darwin.tar.gz` |
| macOS aarch64 | `lvau-aarch64-apple-darwin.tar.gz` |

Each archive contains `lvau-cli`, `lvau-gui`, `lvau-stub`, `README.md`, and `LICENSE` (`.exe` suffix on Windows). Verify downloads with the release `checksums.txt`.

### Windows PowerShell

```powershell
# Download and extract to a directory in your PATH
Invoke-WebRequest -Uri "https://github.com/lasder-ca/lvau/releases/latest/download/lvau-x86_64-pc-windows-msvc.zip" -OutFile lvau.zip
Expand-Archive lvau.zip -DestinationPath "$env:LOCALAPPDATA\lvau"
$env:PATH += ";$env:LOCALAPPDATA\lvau\lvau-x86_64-pc-windows-msvc"
```

### Linux Shell

```sh
curl -LO "https://github.com/lasder-ca/lvau/releases/latest/download/lvau-x86_64-unknown-linux-gnu.tar.gz"
tar xzf lvau-x86_64-unknown-linux-gnu.tar.gz
sudo cp lvau-x86_64-unknown-linux-gnu/lvau-cli /usr/local/bin/
```

### Build From Source

```sh
git clone https://github.com/lasder-ca/lvau.git
cd lvau
cargo build --workspace --release
```

Binaries are written to `target/release/`.

## CLI Usage

```text
lvau-cli <COMMAND> [OPTIONS]

Commands:
  encrypt          Encrypt a file
  decrypt          Decrypt a file
  inspect          Inspect public envelope metadata
  keygen           Generate an experimental hybrid keypair
  verify           Verify file integrity without writing plaintext to disk
  bundle           Pack, extract, inspect, or verify encrypted directory bundles
  sign-keygen      Generate an Ed25519 signing keypair
  sign             Sign an encrypted .lvau file
  verify-signature Verify an Ed25519 signature on an .lvau file
  self-test        Run built-in integration tests
  doctor           Print environment diagnostics
```

### Encrypt with a password

```sh
lvau-cli encrypt --in-file document.pdf --out-file document.pdf.lvau --password
```

### Decrypt with a password

```sh
lvau-cli decrypt --in-file document.pdf.lvau --out-file document.pdf --password
```

### Inspect without decrypting

```sh
lvau-cli inspect --in-file document.pdf.lvau
lvau-cli inspect --in-file document.pdf.lvau --json
```

### Verify integrity without decrypting to disk

```sh
lvau-cli verify --in-file document.pdf.lvau --password
```

### Choose a profile

```sh
lvau-cli encrypt --in-file data.bin --out-file data.bin.lvau --password --profile archive
```

| Profile | Argon2id memory | Intended use |
| --- | ---: | --- |
| `fast` | 16 MiB | Tests and quick local operations |
| `balanced` | 64 MiB | Default general use |
| `archive` | 256 MiB | Slower archival encryption |
| `paranoid` | 1 GiB | Experimental cascade profile |
| `extreme` | 1 GiB | Experimental cascade plus LCO obfuscation |

### Generate and use an experimental hybrid keypair

```sh
lvau-cli keygen --out-base my-identity
lvau-cli encrypt --in-file input.txt --out-file output.lvau --pub-key my-identity.lvau-pub
lvau-cli decrypt --in-file output.lvau --out-file input.restored.txt --priv-key my-identity.lvau-key
```

### Bundle a directory

```sh
lvau-cli bundle pack --in-dir ./project-secrets/ --out-file secrets.lvau --password
lvau-cli bundle inspect --in-file secrets.lvau
lvau-cli bundle list --in-file secrets.lvau --password
lvau-cli bundle extract --in-file secrets.lvau --out-dir ./restored/ --password
lvau-cli bundle extract --in-file secrets.lvau --out-dir ./restored/ --password --dry-run
```

### Sign and verify

```sh
lvau-cli sign-keygen --out-base maintainer
lvau-cli sign --in-file release.lvau --signing-key maintainer.lvau-sign --out-file release-signed.lvau
lvau-cli verify-signature --in-file release-signed.lvau --verify-key maintainer.lvau-verify
```

Use `--force` to replace existing output files. Without `--force`, Lvau refuses to overwrite.

## GUI

`lvau-gui` provides file selection, password or keypair mode, profile selection, status output, and logs. It is useful for local manual workflows, but CLI reliability is the primary focus.

```sh
cargo run --release --package lvau-gui
```

## Security Model

Lvau is designed for local file encryption at rest. It protects file contents when an attacker obtains the encrypted `.lvau` file but does not know the password or hold the private key.

Lvau does not hide file names, exact filesystem metadata, or approximate plaintext size. It does not protect against malware, keyloggers, compromised operating systems, weak passwords, or stolen private keys.

Lvau has not been formally audited. For sensitive production use, also evaluate established tools such as age, VeraCrypt, Cryptomator, or rclone crypt.

Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before relying on Lvau.

## File Format

Lvau uses a streaming architecture for large file support. `.lvau` files consist of:

- 4-byte envelope length prefix (little-endian)
- postcard-serialized envelope (magic bytes, version, metadata, nonces, authenticated AAD hash, total plaintext length)
- Encrypted ciphertext chunks (1 MiB default size)

The `.lvau` format is not stable before v1.0. See [docs/FORMAT.md](docs/FORMAT.md).

## Architecture

| Crate | Purpose |
| --- | --- |
| `lvau-protocol` | Envelope types and serialization |
| `lvau-core` | Crypto engine, KDF, key management, bundle, signing |
| `lvau-cli` | Command-line interface |
| `lvau-gui` | Native GUI |
| `lvau-stub` | Experimental SFX extractor stub |

## Roadmap

| Version | Theme | Key Features |
| --- | --- | --- |
| **v0.3.0** | Inspectable, signed, sealed | Bundle mode, Ed25519 signatures, hardened tests, docs overhaul |
| **v0.4.0** | Recovery and multi-recipient | Shamir recovery shares, rekey/recipient slots, structured secrets |
| **v1.0** | Stable format | Format freeze, formal audit goal, stable API |

See [docs/ROADMAP.md](docs/ROADMAP.md) for details.

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo build --workspace --release
```

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security Reporting

Do not report sensitive security vulnerabilities as public GitHub issues. See [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
