# Lvau 0.4.0 Release Notes (Candidate)

Lvau 0.4.0 is a security-focused minor release. It keeps the existing CLI and legacy read paths while making new capsules use envelope format v2. A patch release was not appropriate because old Lvau binaries cannot read the new output format and callers need explicit migration guidance.

## Highlights

- Format v2 authenticates the declared plaintext length and immutable envelope fields, including empty payloads, and rejects trailing ciphertext.
- Envelope, recipient, KDF, bundle-manifest, signature, approval, recovery-share, and temporary-file handling are substantially hardened.
- Bundle extraction refuses alias targets that could redirect forced overwrite, and GUI crypto no longer blocks the render thread.
- Format v1 and legacy v0.2 envelopes remain readable. Re-encrypt them with 0.4.0 to obtain v2 protections.
- The vulnerable `sharks` recovery dependency is replaced with corrected `blahaj`; new shares use a random set identifier rather than a hash of the recovered secret.
- RustSec review updated `crossbeam-epoch` for RUSTSEC-2026-0204 and removed unused Postcard/Heapless defaults. The adjacent API moves its SQLite path to SQLx 0.8.6 for RUSTSEC-2024-0363.
- CLI JSON/error stream behavior is more predictable, Unix password files require private permissions, and multi-recipient keypair files work regardless of slot order.
- CI covers Linux, Windows, and macOS, validates release tags and crate versions, pins Actions by commit, and produces checksums, CycloneDX SBOMs, and GitHub artifact attestations.

## Compatibility

- Existing commands and format-v1/v0.2 read support are retained.
- A fixed capsule produced by the v0.3.0 release binary is decrypted in the 0.4.0 test suite.
- Newly encrypted files are format v2 and require Lvau 0.4.0 or later.
- Re-encryption changes the artifact and invalidates old artifact signatures. Verify the old file first, decrypt it, encrypt a new v2 file, then sign the new file.
- Legacy recovery shares remain readable; new share sets use recovery-share version 2.

## Security status

Lvau has not completed a formal independent security audit. Hybrid X25519 + ML-KEM-768 encryption, cascade profiles, LCO, GUI, SFX, approval workflows, and release/recovery annotations remain experimental. Approval/policy metadata does not itself enforce decryption authorization or signer trust.

## Release verification

The authorized tag workflow must pass fmt, Clippy, the full workspace tests, the built-in self-test, and per-target builds. Verify downloaded assets with `checksums.txt` and the GitHub artifact attestation before use.
