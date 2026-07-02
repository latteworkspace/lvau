# v0.1.0 - Boring, Inspectable File Encryption

Lvau v0.1.0 is the first public release candidate for a Rust-based local file encryption toolkit.

## Highlights

- `lvau-cli` with `encrypt`, `decrypt`, `inspect`, and `keygen`
- XChaCha20-Poly1305 AEAD for the default encryption path
- Argon2id password derivation with configurable profiles
- HKDF-SHA256 key separation
- Versioned `.lvau` envelope with inspectable public metadata
- Header authentication data checks and plaintext length validation
- Refusal to overwrite output files unless `--force` is supplied
- Native `lvau-gui`
- Experimental X25519 + ML-KEM-768 keypair encryption
- Experimental Windows SFX support through `lvau-stub`

## Release Assets

- `lvau-x86_64-unknown-linux-gnu.tar.gz`
- `lvau-x86_64-pc-windows-msvc.zip`
- `lvau-x86_64-apple-darwin.tar.gz`
- `lvau-aarch64-apple-darwin.tar.gz`
- `checksums.txt`

Each archive includes `lvau-cli`, `lvau-gui`, `lvau-stub`, `README.md`, and `LICENSE`.

## Security Notes

Lvau has not been formally audited. The project uses standard cryptographic primitives through Rust crates, but the integration, envelope format, and key management code need more review before high-risk production use.

The `.lvau` format is not stable before v1.0.

The `extreme` profile includes an LCO obfuscation layer. LCO is not a cryptographic security boundary.

## Known Limitations

- Entire files are currently read into memory.
- File names, filesystem metadata, and approximate plaintext size are not hidden.
- Windows private key ACL hardening is not implemented; Unix private key files are written with mode `0600` where supported.
- Hybrid keypair encryption, cascade profiles, GUI, and SFX should be treated as experimental in v0.1.0.

## Verify Downloads

```sh
sha256sum -c checksums.txt
```

PowerShell:

```powershell
Get-FileHash .\lvau-cli.exe -Algorithm SHA256
```

Report sensitive security issues privately. See `SECURITY.md`.
