# v0.2.0 "Supreme" - Streaming, ACLs & Security Fixes

Lvau v0.2.0 brings massive improvements to performance and security!

## Highlights

- **Streaming Encryption/Decryption**: Entire files are no longer read into memory! Files are now processed in 1 MB chunks, enabling encryption of massive files with minimal RAM usage.
- **Windows ACL Hardening**: Private key files on Windows are now properly secured using `SetNamedSecurityInfoW`, ensuring only the owner can read them (parity with Unix `0600`).
- **Global Chunk Indexing**: AEAD Additional Authenticated Data (AAD) now includes a global chunk index, mitigating chunk reordering/swapping attacks in the streaming format.
- **Key Wrapping Upgrade**: FEK wrapping now uses XChaCha20-Poly1305 instead of AES-GCM for consistency and security.
- **Improved Hybrid Cryptography**: Fixed nonce issues in the X25519 + ML-KEM-768 hybrid key wrapping.

## Release Assets

- `lvau-x86_64-unknown-linux-gnu.tar.gz`
- `lvau-x86_64-pc-windows-msvc.zip`
- `lvau-x86_64-apple-darwin.tar.gz` (Built via M1 cross-compilation for speed)
- `lvau-aarch64-apple-darwin.tar.gz`
- `checksums.txt`

## Security Notes

Lvau has not been formally audited. The project uses standard cryptographic primitives, but the integration, envelope format, and key management code need more review before high-risk production use.
The `.lvau` format is not stable before v1.0.

## Verify Downloads

```sh
sha256sum -c checksums.txt
```

PowerShell:

```powershell
Get-FileHash .\lvau-cli.exe -Algorithm SHA256
```
