# Preflight Inspection

`preflight` parses and validates the public envelope without decrypting the
payload:

```sh
lvau-cli preflight --in-file artifact.lvau
lvau-cli preflight \
  --in-file artifact.lvau \
  --verify-key author.lvau-verify \
  --policy policy.toml \
  --json
```

It reports format version, content type, profile, payload algorithm, recipient
count, public commitment consistency, workflow metadata, experimental flags,
policy results, and author-signature status. Status is `Ok`, `Warn`, or `Fail`.
Malformed, oversized, truncated, resource-invalid, or unsupported envelopes
fail parsing. Legacy v1 files warn that several public fields are not bound to
the payload commitment.

An author signature is verified only when `--verify-key` is supplied. Without
that key, a present signature produces a warning and is not an identity claim.
Approval fingerprints are listed but not verified by preflight. Policy presence
checks have the limitations documented in [CAPSULE_POLICY.md](CAPSULE_POLICY.md).

The public hash is not a signature or MAC: an attacker can rewrite an unsigned
envelope and recompute it. Its cryptographic authority comes only when the v2
payload successfully authenticates against the same commitment, or when the
capsule is verified with a trusted author/approval key.

`inspect` is intended for basic public metadata. `preflight` adds validation,
warnings, optional signature verification, and optional policy linting. Neither
command proves that a password/private key works; use `verify` or `report` with
credentials for that check.
