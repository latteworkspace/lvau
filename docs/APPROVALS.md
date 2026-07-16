# Approval Seals

Approval seals are advisory Ed25519 attestations attached to a capsule. They
support review workflows, but they are **not** M-of-N decryption keys and do not
prevent a holder of the password or private key from decrypting. Lvau does not
currently gate `decrypt` or `bundle extract` on approval count.

## Create and verify a seal

Create a signing key and distribute its `.lvau-verify` public key through a
trusted channel:

```sh
lvau-cli sign-keygen --out-base manager_key
lvau-cli approve \
  --in-file bundle.lvau \
  --out-file bundle-approved.lvau \
  --signing-key manager_key.lvau-sign \
  --comment "reviewed for release"
lvau-cli approvals \
  --in-file bundle-approved.lvau \
  --verify-key manager_key.lvau-verify
```

Each additional approver reads the previous output and writes a new output.
Keep the private `.lvau-sign` file secret; only the `.lvau-verify` file should
be shared for verification.

V2 seals commit to the public envelope (excluding the approval list), all
ciphertext, the approving-key fingerprint, and the approval comment. V1 seals
cover only the legacy `aad_hash` and provide weaker evidence.

## Policy counts are not trust decisions

`require_approval_signatures_min` counts distinct stored signer fingerprints.
Policy lint does not verify every seal, prove that the fingerprints belong to
authorized people, or enforce decryption authorization. A forged record can be
present but invalid. Verify each required key explicitly with `approvals`, then
apply organization-specific identity and threshold rules outside Lvau.

`preflight` lists approval fingerprints but likewise does not cryptographically
verify them. Treat an unverified fingerprint as attacker-controlled metadata.

For a true threshold-decryption design, the cryptographic key material itself
must be threshold-controlled. That feature is not implemented by approval
seals.
