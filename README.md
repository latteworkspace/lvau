# Lvau

> Inspectable encrypted capsules for local files and developer workflows.

Lvau is an experimental Rust workspace for local file encryption. It contains a CLI, a native GUI, a reusable cryptographic library, the versioned `.lvau` file format, and an experimental self-extracting stub. The current release is **0.5.0**.

English | [日本語](README_ja.md)

[![CI](https://github.com/lasder-ca/lvau/actions/workflows/ci.yml/badge.svg)](https://github.com/lasder-ca/lvau/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> [!WARNING]
> Lvau has not completed an independent security audit, and formats may change before 1.0. Read [SECURITY.md](SECURITY.md) and [the threat model](docs/THREAT_MODEL.md) before using it for important data.

## What Lvau provides

- password encryption with XChaCha20-Poly1305, Argon2id, and HKDF-SHA256;
- streaming encryption for ordinary files without loading the full plaintext into memory;
- public inspection of format information without decrypting the payload;
- authenticated decrypt and verify operations with machine-readable JSON output;
- Ed25519 author signatures;
- password-encrypted directory bundles with encrypted manifests;
- advisory local policy checks and preflight reports, plus recipient groups, recovery shares, and structured-secret commands;
- a native GUI that reuses `lvau-core` rather than reimplementing cryptography.

Policy linting is experimental and advisory. It is not automatically enforced by `decrypt` or `bundle extract`; run `policy lint` or `preflight` as a separate workflow step when a local policy must pass before decryption or extraction.

Hybrid recipient encryption, cascade profiles, approval metadata, recovery workflows, the GUI, and self-extracting archives remain experimental.

## Quick start

Password input is hidden and is not written to standard output.

```sh
lvau-cli encrypt --password --in-file secret.txt --out-file secret.txt.lvau
lvau-cli inspect --in-file secret.txt.lvau
lvau-cli verify --password --in-file secret.txt.lvau
lvau-cli decrypt --password --in-file secret.txt.lvau --out-file secret.restored.txt
```

For local non-interactive automation, use a password file with restricted permissions:

```sh
printf '%s' 'replace-with-a-strong-passphrase' > password.txt
chmod 600 password.txt
lvau-cli encrypt --in-file secret.txt --out-file secret.txt.lvau --password-file password.txt
```

On Windows, restrict the password file's ACL to the account that runs Lvau. The CLI's broad-permission check is Unix-only, so it does not reject an overly permissive Windows ACL.

Never commit passwords, private keys, seeds, recovery shares, or credential files.

## Changes in 0.5.0

- Directory bundles stream file contents through a fixed 64 KiB buffer instead of collecting the complete plaintext payload in memory.
- Packing performs two-pass size and BLAKE3 validation; extraction authenticates all entries before creating named outputs atomically.
- Format-v2 HKDF labels, nonce derivation, and chunk AAD are centralized in a versioned suite registry with fixed compatibility vectors.
- The workspace uses `secrecy` 0.10 and `x25519-dalek` 3.
- Inspect, verify, preflight, report, and policy-lint JSON output uses schema version 1.
- Version 0.5.0 still writes envelope format v2. Experimental format v3 is planned separately for 0.6.0.

See [CHANGELOG.md](CHANGELOG.md), [docs/JSON_OUTPUT.md](docs/JSON_OUTPUT.md), and [docs/ROADMAP.md](docs/ROADMAP.md).

## Installation

Release archives are published through [GitHub Releases](https://github.com/lasder-ca/lvau/releases) after an authorized tag workflow succeeds.

Build from source:

```sh
git clone https://github.com/lasder-ca/lvau.git
cd lvau
cargo build --locked --workspace --release
```

Binaries are written to `target/release/`.

## CLI

Run `lvau-cli <command> --help` for the authoritative options.

```text
keygen  encrypt  decrypt  inspect  verify  preflight  report  policy
bundle  sign-keygen  sign  verify-signature  approve  approvals
release  recipients  recovery  secret  self-test  doctor
```

Common examples:

```sh
# Password encryption and verification
lvau-cli encrypt --password --in-file document.pdf --out-file document.pdf.lvau --profile balanced
lvau-cli verify --password --in-file document.pdf.lvau --json
lvau-cli decrypt --password --in-file document.pdf.lvau --out-file document.pdf

# Password-protected directory bundle
lvau-cli bundle pack --password --in-dir ./project-secrets --out-file secrets.lvau
lvau-cli bundle verify --password --in-file secrets.lvau
lvau-cli bundle extract --password --in-file secrets.lvau --out-dir ./restored --dry-run
lvau-cli bundle extract --password --in-file secrets.lvau --out-dir ./restored

# Author signature
lvau-cli sign-keygen --out-base maintainer
lvau-cli sign --in-file secrets.lvau --out-file secrets-signed.lvau --signing-key maintainer.lvau-sign
lvau-cli verify-signature --in-file secrets-signed.lvau --verify-key maintainer.lvau-verify
```

## Security profiles

| Profile | Argon2id parameters | Payload path | Status |
|---|---|---|---|
| `fast` | 16 MiB, 1 iteration, 1 lane | XChaCha20-Poly1305 | Tests and short local work |
| `balanced` | 64 MiB, 2 iterations, 1 lane | XChaCha20-Poly1305 | Default |
| `archive` | 256 MiB, 3 iterations, 2 lanes | XChaCha20-Poly1305 | Infrequent archival work |
| `paranoid` | 1 GiB, 4 iterations, 4 lanes | AES-GCM + XChaCha cascade | Experimental |
| `extreme` | 1 GiB, 4 iterations, 4 lanes | Cascade + LCO | Experimental; LCO is obfuscation, not a security boundary |

## GUI

`lvau-gui` provides an experimental desktop interface for local encryption, decryption, and hybrid key generation. It calls `lvau-core` for cryptographic operations and does not yet expose every CLI workflow.

```sh
cargo run --locked --release --package lvau-gui
```

## Security and format limits

Lvau can protect payload confidentiality and integrity only while passwords, private keys, and the local machine remain secure. It does not protect against malware, keyloggers, a compromised operating system, weak passwords, stolen keys, malicious output consumers, or loss of every credential.

The envelope exposes algorithm identifiers, KDF parameters, recipient slots, nonces, approximate plaintext size, and optional public labels. Bundle paths and file metadata are encrypted by default. Signatures, approvals, releases, and recovery fields are separate annotations and must be verified and interpreted explicitly.

See [docs/FORMAT.md](docs/FORMAT.md) for the v2/v1 layout and migration guidance.

## Architecture

| Crate | Responsibility |
|---|---|
| `lvau-protocol` | Serialized envelope and manifest data types |
| `lvau-core` | Cryptography, parsing, files, bundles, signatures, policies, and recovery |
| `lvau-cli` | Command-line interface and automation output |
| `lvau-gui` | Experimental native interface over `lvau-core` |
| `lvau-stub` | Experimental self-extracting archive support |

The public website is maintained in `lasder-ca/lattes.jp`. The OCI-hosted service is maintained separately; this Rust workspace does not contain cloud credentials or an OCI control-plane client.

## Development

The documented local workflow uses WSL2 with Ubuntu 26.04.

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
cargo build --locked --workspace --release
cargo tree --duplicates
cargo run --locked --quiet --package lvau-cli -- self-test
```

Read [AGENTS.md](AGENTS.md), [CONTRIBUTING.md](CONTRIBUTING.md), and [docs/ROADMAP.md](docs/ROADMAP.md). Report sensitive vulnerabilities through [SECURITY.md](SECURITY.md), not a public issue.

## License

Lvau is available under the [MIT License](LICENSE).
