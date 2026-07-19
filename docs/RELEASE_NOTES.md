# Lvau 0.5.0

Lvau 0.5.0 is a scalability and cryptographic-foundation release. It does not introduce a new encrypted-file format: new output remains envelope v2, and supported v1/v2 input remains readable.

## Highlights

- Bounded-memory directory bundles with a fixed 64 KiB content buffer.
- Two-pass source validation during packing and authenticate-before-write extraction.
- Atomic per-file bundle extraction with no partial named plaintext outputs on failure.
- Versioned payload-suite registry and compatibility-fixed HKDF, nonce, and AAD helpers.
- `secrecy` 0.10 and `x25519-dalek` 3 dependency migrations.
- JSON output schema version 1 for automation-facing commands.

## Compatibility

The bundle payload layout and envelope-v2 cryptographic construction are unchanged. Existing format-v1 and format-v2 capsules remain readable. LCO remains legacy experimental obfuscation and is not treated as an encryption layer.

## Security status

Lvau remains unaudited and pre-1.0. This release should not be described as formally audited, unbreakable, military-grade, or suitable for protecting critical data without independent evaluation.
