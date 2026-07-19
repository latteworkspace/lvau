# Lvau

> Inspectable encrypted capsules for local files and developer workflows.

Lvau is a Rust workspace containing a CLI, native GUI, crypto library, versioned `.lvau` protocol, and an experimental self-extracting stub. The current release is **0.5.0**.

English | [日本語](README_ja.md)

[![CI](https://github.com/latteworkspace/lvau/actions/workflows/ci.yml/badge.svg)](https://github.com/latteworkspace/lvau/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> **Security warning:** Lvau has not completed a formal independent security audit, and the format is not stable before 1.0. Read [SECURITY.md](SECURITY.md) and [the threat model](docs/THREAT_MODEL.md) before using it for important data.

## Quick start

Interactive password entry is hidden and written to the terminal, not stdout:

```sh
lvau-cli encrypt --password --in-file secret.txt --out-file secret.txt.lvau
lvau-cli inspect --in-file secret.txt.lvau
lvau-cli decrypt --password --in-file secret.txt.lvau --out-file secret.restored.txt
```

For non-interactive local automation, use a restricted password file. Lvau removes trailing CR/LF characters but preserves all other bytes. Unix password/seed files must not be accessible by group or other users.

```sh
printf '%s' 'replace-with-a-strong-passphrase' > password.txt
chmod 600 password.txt
lvau-cli encrypt --in-file secret.txt --out-file secret.txt.lvau --password-file password.txt
```

On Windows, restrict the file ACL to the account running Lvau. Password-file ACLs are not automatically validated there. Never commit password or seed files.

## 0.5.0 changes

- Directory bundles now stream file contents through a fixed 64 KiB buffer instead of collecting the complete plaintext payload in memory. The encrypted payload layout remains format-v2 compatible.
- Pack performs two-pass size/BLAKE3 validation, and extract authenticates all entries before atomically creating named outputs.
- Existing v2 HKDF labels, nonce derivation, and chunk AAD are centralized behind a versioned suite registry with fixed compatibility vectors.
- `secrecy` 0.10 and `x25519-dalek` 3 migrations are complete.
- Machine-readable inspect, verify, preflight, report, and policy-lint output uses JSON schema version 1.
- Lvau still writes envelope v2 in this release; experimental format v3 is planned separately for 0.6.0.

See [CHANGELOG.md](CHANGELOG.md), [the JSON contract](docs/JSON_OUTPUT.md), and [the roadmap](docs/ROADMAP.md) for details.

## 0.4.0 changes

- New files use envelope format v2. The AEAD commitment now includes the declared plaintext length, nonces, recipients/KDF header, public label, content type, private metadata bytes, and policy-override marker.
- Empty payloads contain an authenticated AEAD frame, and decryptors reject trailing ciphertext.
- Readers retain format-v1 and legacy v0.2 envelope compatibility through a bounded, exact parser. Legacy format-v1 length and non-header metadata were not payload-authenticated; decrypt and re-encrypt old capsules to migrate them to v2.
- Envelope size, recipient count/type, wrapped-key sizes, nonce layout, and exact Argon2id profile tuples are validated before expensive work.
- Author signatures and approval seals commit to their fingerprints and comments; v2 approval seals also commit to the ciphertext. They still require explicit trusted-key verification.
- Bundle manifests now receive canonical decoding, checked offsets, overlap/path/collision validation, and per-entry BLAKE3 verification.
- Bundle packing rejects special files; extraction will not overwrite symlink/reparse-point or multi-hardlink targets, even with `--force`.
- Recovery shares no longer publish `SHA-256(secret)` as a set identifier and use the corrected `blahaj` Shamir implementation.
- Sensitive outputs use same-directory temporary files, fsync, restrictive Unix modes, and atomic replacement where the platform supports it.
- GUI crypto runs on a background worker with processed-byte status; password/seed fields are cleared after dispatch, and experimental SFX assembly streams into an atomic temporary output.
- CI validates Linux, Windows, and macOS, pins Actions by commit, checks release tags against every workspace crate, and prepares checksums, CycloneDX SBOMs, and GitHub artifact attestations.

See [CHANGELOG.md](CHANGELOG.md) and [the generic release notes](docs/RELEASE_NOTES.md) for the complete candidate summary.

## Supported and experimental features

Stable-enough-to-test paths:

- Password encryption with XChaCha20-Poly1305, Argon2id, and HKDF-SHA256.
- Streaming 1 MiB chunks without loading a whole ordinary file into memory.
- Public inspection, authenticated decrypt/verify, JSON inspect/verify/preflight output, and overwrite refusal unless `--force` is supplied.
- Ed25519 author signatures.
- Password-encrypted directory bundles with an encrypted manifest.
- Local capsule-policy linting, preflight reports, recipient-group files, recovery shares, and structured-secret commands.

Experimental paths:

- X25519 + ML-KEM-768 hybrid recipient encryption.
- `paranoid` and `extreme` cascade profiles.
- LCO in `extreme`; it is obfuscation, not a cryptographic security boundary.
- Native GUI and Windows self-extracting archives.
- Approval seals, release metadata, and recovery metadata as workflow annotations.

Policy and approval checks are advisory local controls. Their presence does **not** enforce decryption authorization, establish signer trust, or replace an external M-of-N authorization system. See [docs/APPROVALS.md](docs/APPROVALS.md) and [docs/CAPSULE_POLICY.md](docs/CAPSULE_POLICY.md).

## Install

Release archives are published at [GitHub Releases](https://github.com/latteworkspace/lvau/releases) only after an authorized tag workflow completes.

| Platform | Planned asset name |
| --- | --- |
| Linux x86_64 | `lvau-x86_64-unknown-linux-gnu.tar.gz` |
| Windows x86_64 | `lvau-x86_64-pc-windows-msvc.zip` |
| macOS x86_64 | `lvau-x86_64-apple-darwin.tar.gz` |
| macOS aarch64 | `lvau-aarch64-apple-darwin.tar.gz` |

Verify an archive against `checksums.txt`, then verify its GitHub artifact attestation with GitHub CLI when available. Each archive contains `lvau-cli`, `lvau-gui`, `lvau-stub`, both READMEs, `SECURITY.md`, and `LICENSE` (`.exe` suffix on Windows).

### Build from source

```sh
git clone https://github.com/latteworkspace/lvau.git
cd lvau
cargo build --locked --workspace --release
```

Binaries are written to `target/release/`.

### Windows Explorer context menu

The existing helper can register a per-user `Lvau` context menu without administrator privileges. It decrypts `.lvau` files and encrypts other files, creates output beside the input, refuses to overwrite, and prompts for a password each time.

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\install-context-menu.ps1 `
  -BinaryPath .\target\release\lvau-cli.exe
```

Remove it with:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\uninstall-context-menu.ps1
```

## CLI

Run `lvau-cli <command> --help` for the authoritative options. Top-level commands are:

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

# Experimental hybrid recipient encryption
lvau-cli keygen --out-base identity
lvau-cli encrypt --in-file input.txt --out-file output.lvau --pub-key identity.lvau-pub
lvau-cli decrypt --in-file output.lvau --out-file restored.txt --priv-key identity.lvau-key

# Password bundle
lvau-cli bundle pack --password --in-dir ./project-secrets --out-file secrets.lvau
lvau-cli bundle inspect --in-file secrets.lvau
lvau-cli bundle list --password --in-file secrets.lvau
lvau-cli bundle verify --password --in-file secrets.lvau
lvau-cli bundle extract --password --in-file secrets.lvau --out-dir ./restored --dry-run
lvau-cli bundle extract --password --in-file secrets.lvau --out-dir ./restored

# Signature
lvau-cli sign-keygen --out-base maintainer
lvau-cli sign --in-file secrets.lvau --out-file secrets-signed.lvau --signing-key maintainer.lvau-sign
lvau-cli verify-signature --in-file secrets-signed.lvau --verify-key maintainer.lvau-verify
```

Bundle list/extract/verify currently accept password credentials; hybrid bundle extraction is not exposed by the CLI.

### Security profiles

| Profile | Argon2id parameters | Payload path | Status |
| --- | --- | --- | --- |
| `fast` | 16 MiB, 1 iteration, 1 lane | XChaCha20-Poly1305 | Intended for tests/quick local work |
| `balanced` | 64 MiB, 2 iterations, 1 lane | XChaCha20-Poly1305 | Default |
| `archive` | 256 MiB, 3 iterations, 2 lanes | XChaCha20-Poly1305 | Slower archival use |
| `paranoid` | 1 GiB, 4 iterations, 4 lanes | AES-GCM + XChaCha cascade | Experimental |
| `extreme` | 1 GiB, 4 iterations, 4 lanes | Cascade + LCO | Experimental |

### Recovery shares

Recovery operates on a file such as a private key. Protect every share as sensitive material.

```sh
lvau-cli recovery split --in-file identity.lvau-key --shares 5 --threshold 3 --out-dir ./shares
lvau-cli recovery inspect --in-file ./shares/share-1.lvau-share
lvau-cli recovery combine --shares-dir ./shares --out-file restored.lvau-key
```

### Structured secrets

These commands choose output names automatically and prompt interactively. `secret print` intentionally writes plaintext to stdout, so do not use it where logs capture output.

```sh
lvau-cli secret encrypt --in-file .env
lvau-cli secret edit --in-file .env.lvau
lvau-cli secret print --in-file .env.lvau
lvau-cli secret decrypt --in-file .env.lvau
```

## GUI

`lvau-gui` uses `lvau-core` rather than reimplementing crypto. It is an experimental interface for local file encryption/decryption and hybrid key generation; it does not yet expose every CLI workflow.

```sh
cargo run --locked --release --package lvau-gui
```

## Security and format limits

Lvau protects payload confidentiality and integrity when passwords/private keys and the local machine remain secure. It does not protect against malware, keyloggers, a compromised OS, weak passwords, stolen keys, malicious output consumers, or loss of all credentials.

The envelope exposes algorithms, KDF parameters, recipient slots, nonces, approximate plaintext size, and optional public labels. Bundle paths and file metadata are inside the encrypted payload by default. Signature, approval, release, and recovery fields are mutable annotations and must be verified/interpreted separately.

The on-disk layout is a 4-byte little-endian envelope length, a bounded postcard envelope, and authenticated ciphertext chunks. See [docs/FORMAT.md](docs/FORMAT.md) for v2/v1 details and migration guidance.

## Architecture

| Crate | Responsibility |
| --- | --- |
| `lvau-protocol` | Serialized envelope and manifest data types |
| `lvau-core` | Crypto, parsing, files, bundles, signing, policy, and recovery |
| `lvau-cli` | Command-line UX and automation output |
| `lvau-gui` | Experimental native GUI over `lvau-core` |
| `lvau-stub` | Experimental SFX extractor |

The public website is maintained in the adjacent `lattes.jp` repository. The OCI-hosted server API is in the adjacent `lvau-api` repository; the Rust workspace itself contains no OCI SDK or direct OCI control-plane client.

## Development

Use WSL2 with Ubuntu 26.04 for the documented local workflow:

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
cargo build --locked --workspace --release
cargo tree --duplicates
```

Read [AGENTS.md](AGENTS.md), [CONTRIBUTING.md](CONTRIBUTING.md), and [docs/ROADMAP.md](docs/ROADMAP.md). Do not report sensitive vulnerabilities in public issues; use the process in [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
