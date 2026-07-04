# Lvau

> Signed, policy-checked, recoverable encrypted capsules for local files and developer workflows.

Lvau is a Rust-based encrypted capsule toolkit. A Lvau capsule is not just an encrypted file; it can contain an encrypted payload, encrypted private manifest, minimal public metadata, author signature, recipient slots, recovery policy, artifact policy, verification status, and release metadata.

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

Lvau is not trying to replace age, VeraCrypt, Cryptomator, or SOPS. Each tool excels at a specific use case. 

**Honest assessment:**
- **age** is excellent for simple file encryption.
- **VeraCrypt** is excellent for disk/container encryption.
- **Cryptomator** is excellent for cloud-synced vaults.
- **SOPS** is excellent for structured secrets.
- **Lvau** focuses on Rust, inspectable envelopes, signed encrypted artifacts, sealed bundles, recovery workflows, CLI-first automation, and local developer workflows.

### Comparison

| Feature | Lvau | age | VeraCrypt | Cryptomator | SOPS |
| --- | :---: | :---: | :---: | :---: | :---: |
| File encryption | ✅ | ✅ | — | — | — |
| Directory bundles | ✅ | — | — | ✅ | — |
| Disk/container encryption | — | — | ✅ | — | — |
| Cloud vault sync | — | — | — | ✅ | — |
| Structured secrets | ✅ | — | — | — | ✅ |
| Capsule policy & recovery | ✅ | — | — | — | — |
| Signed artifacts & Approvals | ✅ | — | — | — | ✅ |
| CLI automation | ✅ | ✅ | limited | — | ✅ |
| GUI | ✅ | — | ✅ | ✅ | — |
| Formally audited | **no** | **yes** | **yes** | **yes** | varies |
| Implementation | Rust | Go | C++ | Java | Go |

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
- **Recovery shares** — Split keys or files into Shamir Secret Sharing recovery shards.
- **Structured secrets** — Direct CLI commands (`lvau-cli secret`) to encrypt, decrypt, and edit `.env` or API keys securely in-place, integrated with local policies.
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
lvau-cli bundle verify --in-file secrets.lvau --password
lvau-cli bundle extract --in-file secrets.lvau --out-dir ./restored/ --password
lvau-cli bundle extract --in-file secrets.lvau --out-dir ./restored/ --password --dry-run
```

### Sign and verify

```sh
lvau-cli sign-keygen --out-base maintainer
lvau-cli sign --in-file release.lvau --signing-key maintainer.lvau-sign --out-file release-signed.lvau
lvau-cli verify-signature --in-file release-signed.lvau --verify-key maintainer.lvau-verify
```

### Recovery Shares

Split a master key into Shamir shares for secure offline recovery:

```sh
lvau-cli recovery split --in-key my-identity.lvau-key --shares 5 --threshold 3 --out-dir ./shares/
lvau-cli recovery inspect --share ./shares/share-1.lvau-share
lvau-cli recovery combine --shares-dir ./shares/ --out-key restored.lvau-key
```

### Rekey / Recipient Slots

Wrap the data encryption key for multiple recipients without full re-encryption:

```sh
lvau-cli rekey add-recipient --in-file secrets.lvau --out-file secrets-shared.lvau --pub-key alice.lvau-pub
lvau-cli rekey list-recipients --in-file secrets-shared.lvau
lvau-cli rekey remove-recipient --in-file secrets-shared.lvau --out-file secrets-revoked.lvau --recipient 0xABC123
```

### Structured Secret Mode

Lightweight developer workflows for dotfiles and configuration:

```sh
lvau-cli secret encrypt --in-file .env --out-file .env.lvau --format dotenv --password
lvau-cli secret edit --in-file .env.lvau --password
lvau-cli secret print --in-file .env.lvau --password --redact
lvau-cli secret decrypt --in-file .env.lvau --out-file .env --password
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
| **v0.4.0** | Policy-checked capsules | Capsule policy, preflight checks, approval seals, diffs, groups, metadata |
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
