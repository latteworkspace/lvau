# Roadmap

Roadmap items are intentions, not release commitments. The implementation and
`CHANGELOG.md` are authoritative for shipped behavior. Cryptographic features
remain experimental until their format, vectors, migration behavior, and review
status satisfy the promotion gates below.

## 0.4.0 baseline

0.4.0 introduced a v2 envelope commitment while retaining v1 reads, bounded
envelope parsing, stricter resource validation, authenticated empty payloads,
trailing-ciphertext rejection, safer output handling, multi-recipient hybrid
key-pair encryption, recovery-share tooling, structured-secret commands,
policy/preflight reporting, advisory approval seals, and hardened bundle
validation.

The stable default payload remains XChaCha20-Poly1305. AES-GCM cascade profiles,
LCO, hybrid recipients, GUI, SFX, approvals, and recovery workflows remain
experimental. LCO is obfuscation and is not an encryption layer.

## Road to 1.0

The tracked release sequence is maintained in issue #16.

### 0.5.0 — scalable implementation and crypto foundations

Tracking: #10

- stream bundle pack, list, verify, and extract with bounded memory;
- stabilize JSON schema version 1 and CLI automation behavior;
- modularize the CLI without changing commands or exit behavior;
- add real historical fixtures for every supported writer release;
- centralize a versioned crypto-suite registry;
- centralize domain-separated HKDF labels, nonce derivation, and AAD encoding;
- add known-answer vectors before introducing format v3; and
- complete `secrecy` and `x25519-dalek` migrations with source changes and tests.

0.5.0 continues writing format v2. It does not add another wire-format cipher
layer.

### 0.6.0 — experimental format v3 and layered AEAD

Tracking: #11

Introduce v3 as an explicit opt-in writer while preserving v1/v2 reads and
keeping v2 as the default during this release.

Candidate payload suites:

- `LV3-XC20P`: XChaCha20-Poly1305;
- `LV3-AESGCMSIV-XC20P`: AES-256-GCM-SIV inner encryption followed by
  XChaCha20-Poly1305 outer encryption.

Every layer must use an independent key, independent nonce domain, fixed order,
and AAD binding the format version, suite, layer, envelope commitment, chunk
index, lengths, and final-frame state. Decryption must authenticate every layer
before releasing plaintext.

V3 does not include LCO as a security layer. Existing experimental v2 LCO files
remain readable for migration.

### 0.7.0 — recipient suites and post-quantum authentication

Tracking: #12

- define an explicit classical X25519/HPKE-compatible recipient suite;
- add a pure ML-KEM-768 recipient suite using FIPS 203 and NIST KEM guidance;
- keep ML-KEM-768 + X25519 hybrid composition experimental until its
  construction is sufficiently stable and reviewed;
- introduce algorithm-qualified key IDs and fingerprints;
- retain Ed25519 signatures;
- add optional ML-DSA-65 and dual-signature verification policies if vectors,
  implementation review, and interoperability checks pass; and
- preserve legacy v2 hybrid-recipient reads without silently reinterpreting
  their algorithm identifier.

### 0.8.0 — rekey and key rotation

Tracking: #13

- separate the immutable payload core from an authenticated mutable recipient
  table;
- add recipient, password-slot, and KDF rewrap operations without rewriting
  payload ciphertext;
- add explicit full root-key rotation for actual cryptographic revocation;
- document that removing a recipient cannot revoke old copies or secrets already
  obtained; and
- add generation metadata for comparison with trusted external state without
  claiming standalone rollback protection.

### 0.9.0 — format freeze and release candidate

Tracking: #14

- freeze v3 encodings, suite IDs, key-schedule labels, nonce rules, AAD,
  recipient slots, signature structures, JSON contracts, and error classes;
- stop adding cryptographic primitives after the freeze;
- run continuous fuzzing, property tests, differential tests, and malformed
  corpus tests;
- complete cross-platform filesystem, atomic-write, resource-limit, and
  secret-lifetime review;
- publish normative vectors and an independent verifier or decoder;
- document reproducible-build status, provenance, support policy, deprecation,
  and emergency suite disablement; and
- obtain focused independent review of the v3 composition before promotion.

V3 becomes the default writer only if the review and migration gates pass.
Otherwise 1.0 is delayed.

### 1.0.0 — stable format and compatibility contract

Tracking: #15

Candidate stable behavior:

- default password mode: Argon2id, a random 256-bit file root key, and
  XChaCha20-Poly1305 chunk encryption in format v3;
- optional hardened mode: AES-256-GCM-SIV inner encryption plus
  XChaCha20-Poly1305 outer encryption with independently derived keys;
- one reviewed classical recipient suite;
- pure ML-KEM-768 recipient support only if its implementation gates pass;
- hybrid PQ/traditional recipients remain experimental unless their
  construction and integration are sufficiently stable and reviewed;
- stable Ed25519 signatures, with optional ML-DSA-65 only if ready; and
- stable CLI commands, exit-code classes, stdout/stderr behavior, and JSON
  schema version 1.

1.0 continues reading supported v1, v2, and v3 historical fixtures. Patch and
minor releases do not silently change bytes for an existing suite. New
cryptography receives a new suite identifier and begins as explicit opt-in.

## Rules for adding encryption layers

An encryption layer is accepted only when it has:

1. a documented threat it addresses;
2. an independently derived, domain-separated key;
3. an independent nonce domain;
4. an unambiguous fixed position in the suite;
5. AAD that commits to version, suite, order, chunk index, and lengths;
6. fixed known-answer, tamper, and malformed-input vectors;
7. bounded-memory implementation behavior; and
8. a migration, deprecation, and emergency-disable strategy.

Adding another primitive is not automatically stronger. Padding, compression,
hashes, signatures, checksums, and LCO are not encryption layers. Layer count
must never be presented as a numerical security multiplier.

## Promotion gates for supported suites

A suite may move from experimental to supported only after:

- format and key schedule freeze;
- normative positive and negative vectors;
- cross-platform compatibility fixtures;
- fuzzing and resource-limit coverage;
- dependency and implementation review;
- focused independent cryptographic design review;
- accurate threat-model, migration, and limitation documentation; and
- resolution of known high-severity security findings.

## 1.0 readiness criteria

1.0 requires a documented stable format/API policy, complete migration and
fixture matrix, resolved high-severity security findings, reproducible or
accurately characterized release practice, sustained cross-platform testing,
and readiness for independent security review. An audit is desirable but must
never be implied before it has actually occurred.

## Non-goals

- custom cipher invention;
- arbitrary multi-cipher stacking;
- full-disk encryption or mounted encrypted filesystems;
- steganography or plausible deniability;
- guaranteed secure deletion or standalone rollback protection;
- TLS/network-protocol replacement;
- cloud KMS or OCI control-plane behavior in the local file format; and
- claims such as “unbreakable” or “military-grade.”
