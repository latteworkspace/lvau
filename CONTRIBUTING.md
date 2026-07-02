# Contributing to Lvau

Thanks for helping improve Lvau. This project handles security-sensitive code, so small, clear, tested changes are preferred.

## Prerequisites

- Stable Rust and Cargo from <https://rustup.rs/>
- `rustfmt` and `clippy`: `rustup component add rustfmt clippy`

## Build

```sh
git clone https://github.com/lasder-ca/lvau.git
cd lvau
cargo build --workspace
cargo build --workspace --release
```

## Test

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo build --workspace --release
```

## Run the CLI

```sh
cargo run --package lvau-cli -- encrypt --in-file input.txt --out-file output.lvau --password
```

For scripts and CI, use a local password file:

```sh
cargo run --package lvau-cli -- encrypt --in-file input.txt --out-file output.lvau --password-file password.txt
```

## Run the GUI

```sh
cargo run --release --package lvau-gui
```

## Pull Requests

1. Keep the scope focused.
2. Add or update tests for behavior changes.
3. Update docs when commands, formats, release assets, or security wording changes.
4. Run the full check suite before opening the PR.
5. Explain security-sensitive changes clearly.

## Crypto and Format Rules

- Do not introduce custom cryptography as a security boundary.
- Do not weaken Argon2id parameters, nonce generation, AEAD authentication, or key handling.
- Do not change the `.lvau` format without updating `docs/FORMAT.md`, tests, and `CHANGELOG.md`.
- Do not make claims such as "unbreakable", "military-grade", "formally audited", or "production-proven".
- Treat hybrid keypair encryption, cascade profiles, GUI, and SFX as experimental unless the project status changes.

## Security Issues

Do not open public issues for sensitive vulnerabilities. Follow [SECURITY.md](SECURITY.md).

## Useful Labels

- `good first issue`
- `help wanted`
- `documentation`
- `security`
- `crypto`
- `cli`
- `gui`
- `release`
- `format`
