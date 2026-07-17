# Roadmap

Roadmap items are intentions, not release commitments. The implementation and
`CHANGELOG.md` are authoritative for shipped behavior.

## 0.4.0 release candidate

0.4.0 introduces a v2 envelope commitment while retaining v1 reads, bounded
envelope parsing, stricter resource validation, authenticated empty payloads,
trailing-ciphertext rejection, safer output handling, multi-recipient hybrid
key-pair encryption, recovery-share tooling, structured-secret commands,
policy/preflight reporting, advisory approval seals, and hardened bundle
validation.

Release engineering for this candidate includes cross-platform CLI smoke tests,
RustSec checks with time-bounded exceptions, checksums, CycloneDX SBOMs, and
GitHub artifact attestations. It remains experimental and unaudited.

## After 0.4.0

Priorities, in rough order:

- add real historical binary fixtures from every supported writer release;
- stream bundle packing and extraction without buffering the full plaintext;
- further harden extraction against filesystem races and special files;
- modularize the CLI while preserving commands, exit behavior, and JSON output;
- add stable JSON schemas and broader cross-platform integration tests;
- improve GUI cancellation, accessibility, and headless-test coverage;
- define a reviewed recipient-rekey format before implementing add/remove
  operations; and
- decide on a maintainer-controlled release-signing method in addition to
  checksums, SBOMs, and GitHub attestations.

Recipient rekey, value-only structured-secret encryption, cloud KMS wrapping,
OCI SDK/control-plane operations, and threshold decryption are **not** current
features. They require separate designs and compatibility review.

## 1.0 readiness criteria

1.0 requires a documented stable format/API policy, a complete migration and
fixture matrix, resolved high-severity security findings, reproducible release
practice, sustained cross-platform testing, and readiness for independent
security review. An audit is desirable but must never be implied before it has
actually occurred.

## Non-goals

- custom cipher invention;
- full-disk encryption or mounted encrypted filesystems;
- steganography or plausible deniability;
- TLS/network-protocol replacement; and
- claims such as “unbreakable” or “military-grade.”
