# Lvau

> Boring, inspectable file encryption for Rust apps and power users.

Lvau is a Rust-based local file encryption toolkit. It uses standard cryptographic primitives, safe defaults, and a versioned `.lvau` envelope that can be inspected without decrypting the payload.

English | [Japanese](README_ja.md)

[![CI](https://github.com/lasder-ca/lvau/actions/workflows/ci.yml/badge.svg)](https://github.com/lasder-ca/lvau/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

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

## Features

- XChaCha20-Poly1305 AEAD for the default password encryption path.
- Argon2id password KDF with `fast`, `balanced`, `archive`, `paranoid`, and `extreme` profiles.
- HKDF-SHA256 key separation.
- Versioned `.lvau` envelope with magic bytes, version, public KDF metadata, nonces, authenticated header hash, and plaintext length.
- Parallel 1 MiB chunk encryption via Rayon.
- Hidden password prompts in the CLI, plus `--password-file` for non-interactive automation.
- Refuses to overwrite output unless `--force` is provided.
- Native GUI via `egui`.

## Experimental Features

These are available, but should be treated as experimental in v0.2.1:

- Hybrid keypair encryption using X25519 + ML-KEM-768.
- Cascade profiles (`paranoid`, `extreme`).
- The LCO layer used by `extreme`. LCO is an obfuscation layer, not a cryptographic security boundary.
- Windows self-extracting archives (`--sfx`).

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
  encrypt     Encrypt a file
  decrypt     Decrypt a file
  inspect     Inspect public envelope metadata
  keygen      Generate an experimental hybrid keypair
  verify      Verify file integrity without writing plaintext to disk
  self-test   Run built-in integration tests
  doctor      Print environment diagnostics
```

Encrypt with a password:

```sh
lvau-cli encrypt --in-file document.pdf --out-file document.pdf.lvau --password
```

Decrypt with a password:

```sh
lvau-cli decrypt --in-file document.pdf.lvau --out-file document.pdf --password
```

Inspect without decrypting:

```sh
lvau-cli inspect --in-file document.pdf.lvau
```

Verify integrity without decrypting to disk:

```sh
lvau-cli verify --in-file document.pdf.lvau --password
```

Choose a profile:

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

Generate and use an experimental hybrid keypair:

```sh
lvau-cli keygen --out-base my-identity
lvau-cli encrypt --in-file input.txt --out-file output.lvau --pub-key my-identity.lvau-pub
lvau-cli decrypt --in-file output.lvau --out-file input.restored.txt --priv-key my-identity.lvau-key
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
| `lvau-core` | Crypto engine, KDF, key management, file operations |
| `lvau-cli` | Command-line interface |
| `lvau-gui` | Native GUI |
| `lvau-stub` | Experimental SFX extractor stub |

## Comparison

Lvau does not claim to be better or more secure than age, VeraCrypt, Cryptomator, or rclone crypt. Lvau focuses on a Rust implementation, local file workflows, inspectable envelope metadata, and a CLI-first experience.

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
