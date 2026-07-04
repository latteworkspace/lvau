# Approval Seals

Lvau allows you to add secondary Ed25519 signatures, known as **Approval Seals**, to an already encrypted `.lvau` capsule.

## Why use Approval Seals?

Imagine a workflow where a developer encrypts a configuration bundle and signs it with their personal key. Before this bundle can be deployed to production, it needs to be approved by a QA team or a CI/CD pipeline.

The CI/CD pipeline does not (and should not) have the password or private key to decrypt the bundle. However, it can run `lvau-cli preflight` and other linting tools on the public metadata. Once satisfied, the CI/CD pipeline can apply an *Approval Seal* to the capsule using its own Ed25519 signing key.

When the production server receives the capsule, its `CapsulePolicy` can require *both* the developer's original signature *and* the CI/CD pipeline's approval seal before it will decrypt the payload.

## How it Works

An approval seal is an Ed25519 signature over the capsule's internal `aad_hash`. Because it only signs the hash (which is guaranteed by the AEAD construction to match the payload and headers), the approving party does not need to decrypt or unpack the file.

### Adding an Approval

```sh
# The CI/CD pipeline adds an approval seal
lvau-cli approve --in-file bundle.lvau \
    --out-file bundle-approved.lvau \
    --signing-key ci_pipeline.lvau-sign \
    --comment "Passed integration tests"
```

### Verifying Approvals

You can verify that a specific seal is present on a capsule without decrypting it:

```sh
lvau-cli approvals --in-file bundle-approved.lvau \
    --verify-key ci_pipeline.lvau-verify
```

Alternatively, you can enforce the presence of this approval seal via a `CapsulePolicy` (see [CAPSULE_POLICY.md](CAPSULE_POLICY.md)).
