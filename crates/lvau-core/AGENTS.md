# `lvau-core` Security Instructions

These rules add to the repository-level `AGENTS.md`.

- Treat envelope bytes, recipient slots, KDF parameters, ciphertext, bundle
  manifests, recovery shares, signature records, and filesystem paths as
  attacker-controlled.
- Preserve v1 decoding exactly. New encryption uses v2; changing the v2
  commitment, nonce derivation, frame layout, key derivation, or signature
  statement requires a new format/version design, not an in-place edit.
- Keep payload keys, password-derived keys, shared secrets, and reconstructed
  recovery secrets in zeroizing containers where practical. Do not add secret
  values to errors or `Debug` output.
- Maintain explicit upper bounds and checked arithmetic before allocation or
  slicing. Tests must cover malformed length, overflow, truncation, trailing
  bytes, wrong password/key, tampering, empty payloads, and unsupported resource
  combinations.
- Bundle extraction must reject absolute/parent paths, portable collisions,
  symlink escapes, overlaps, out-of-bounds data, hash mismatch, special files,
  and unrequested overwrite. Test on Unix and account for Windows path rules.
- Authentication must complete before a requested plaintext output is
  persisted. Use a temporary file in the destination directory, `sync_all`,
  atomic persistence where supported, and restrictive modes.
- Approval/policy/recovery metadata is not decryption authorization. Do not
  infer signer trust from record presence or fingerprint text.

After any change here, run the full workspace checks plus targeted legacy,
tamper, resource-bound, bundle, signature/approval, and recovery tests. Review
`docs/FORMAT.md` and `docs/THREAT_MODEL.md` for required updates.
