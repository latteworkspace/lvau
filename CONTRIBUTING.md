# Contributing to Lvau

Thank you for your interest in contributing to Lvau! This guide covers how to build, test, and submit changes.

## Prerequisites

- [Rust and Cargo](https://rustup.rs/) (stable toolchain)
- `rustfmt` and `clippy` components: `rustup component add rustfmt clippy`

## Build

```sh
# Clone the repository
git clone https://github.com/lasder-ca/lvau.git
cd lvau

# Build the entire workspace
cargo build

# Build in release mode
cargo build --release
```

## Test

```sh
# Run all tests
cargo test --workspace

# Run tests with output
cargo test --workspace -- --nocapture
```

## Run the CLI

```sh
# Run from cargo
cargo run --package lvau-cli -- encrypt --in-file input.txt --out-file output.lvau --password

# Or build first, then run the binary
cargo build --release
./target/release/lvau-cli encrypt --in-file input.txt --out-file output.lvau --password
```

## Run the GUI

```sh
cargo run --release --package lvau-gui
```

## Code style

- Run `cargo fmt --all` before committing
- Run `cargo clippy --workspace --all-targets` and fix any warnings
- Follow existing naming conventions and module structure
- Keep functions focused and testable
- Add doc comments for public APIs

## Submitting changes

1. Fork the repository
2. Create a feature branch: `git checkout -b my-feature`
3. Make your changes
4. Run the full check suite:
   ```sh
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets
   cargo test --workspace
   cargo build --workspace
   ```
5. Commit with a clear message
6. Open a pull request

## Security-sensitive contributions

If your change touches any of the following areas, additional care is required:

- **Cryptographic code** (`lvau-core/src/crypto/`)
- **Envelope format** (`lvau-protocol/src/`)
- **Key management** (`keys.rs`)
- **KDF parameters** or password handling

### Rules for crypto changes

1. **No custom cryptography as a security boundary.** Lvau uses standard primitives (XChaCha20-Poly1305, AES-256-GCM, Argon2id, HKDF-SHA256). Do not introduce custom ciphers or constructions that users would rely on for security.
2. **Tests required.** Every change to cryptographic code must include or update tests — at minimum a roundtrip test and a wrong-key test.
3. **Explain your reasoning.** Crypto PRs should include a clear description of what changed and why.
4. **Don't weaken defaults.** Do not reduce KDF cost parameters, remove AEAD authentication, or skip nonce generation.

### Reporting security issues

If you find a security vulnerability, **do not** open a public issue. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## Labels

When creating issues, these labels help us triage:

- `good first issue` — suitable for new contributors
- `help wanted` — we'd appreciate community help
- `documentation` — docs improvements
- `security` — security-related
- `crypto` — cryptographic implementation
- `cli` — CLI-related
- `gui` — GUI-related
- `release` — release process
- `format` — envelope format

## Questions?

Open a [Discussion](https://github.com/lasder-ca/lvau/discussions) or an issue. We're happy to help.
