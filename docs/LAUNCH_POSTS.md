# Launch Posts

Draft posts for announcing Lvau v0.1.0.

---

## X / Twitter

```
I built Lvau — boring, inspectable file encryption in Rust.

It uses standard cryptographic primitives, safe defaults, and a versioned .lvau envelope that can be inspected without decrypting the payload.

CLI-first, GUI-supported, local-first.

v0.1.0 is out: https://github.com/lasder-ca/lvau
```

---

## Reddit / Hacker News

### Title

Lvau — Boring, inspectable file encryption for Rust apps and power users

### Body

```
I've been working on Lvau, a file encryption toolkit in Rust. v0.1.0 is the first public release.

**What it does:**
- Encrypts individual files with a password or hybrid keypair
- Uses XChaCha20-Poly1305 (AEAD) with Argon2id key derivation
- Writes a versioned `.lvau` envelope with inspectable metadata
- CLI-first, with a native GUI available (egui)

**Design philosophy:**
- Standard, boring cryptography — no custom ciphers as a security boundary
- Safe defaults — strong KDF parameters out of the box
- Inspectable format — you can read the envelope metadata without decrypting
- Honest documentation — clear threat model, no overclaiming

**What it is NOT:**
- Not a replacement for age, VeraCrypt, Cryptomator, or rclone crypt — each has different strengths
- Not formally audited — the threat model and SECURITY.md are upfront about this
- Not stable yet — the format may change before v1.0

**Technical details:**
- Argon2id KDF with configurable cost profiles (16 MB to 1 GB)
- HKDF-SHA256 key separation
- Parallel 1 MB chunked encryption via Rayon
- Experimental X25519 + ML-KEM-768 hybrid keypair support
- Self-extracting archive (SFX) support
- Zeroized key material via the `zeroize` crate

The code is MIT-licensed. I'd appreciate feedback on the design, threat model, and format specification.

GitHub: https://github.com/lasder-ca/lvau
Threat model: https://github.com/lasder-ca/lvau/blob/main/docs/THREAT_MODEL.md
Format spec: https://github.com/lasder-ca/lvau/blob/main/docs/FORMAT.md
```

---

## GitHub Discussions (announcement)

### Title

v0.1.0 released — Boring, inspectable file encryption

### Body

```
Lvau v0.1.0 is the first public release.

This release includes:
- CLI and GUI for file encryption/decryption
- XChaCha20-Poly1305 with Argon2id key derivation
- Versioned `.lvau` envelope with inspectable metadata
- Pre-built binaries for Linux, Windows, and macOS

Please see the release notes for details, known limitations, and security disclaimers:
https://github.com/lasder-ca/lvau/releases/tag/v0.1.0

Feedback, bug reports, and security reviews are very welcome.
```
