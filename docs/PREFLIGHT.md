# Preflight Verification

In many workflows, you want to inspect or verify an encrypted capsule *before* you prompt the user for a password or load a private key into memory.

Lvau provides a dedicated **Preflight** command for exactly this purpose. 

## What is Preflight?

The `lvau-cli preflight` command analyzes the public metadata envelope of a `.lvau` file without decrypting the payload. It checks:
- **Envelope Integrity**: Validates the magic bytes, format version, and ensures the header hasn't been structurally corrupted.
- **AAD Hash**: Verifies that the public header hasn't been maliciously modified since it was created.
- **Signature (Optional)**: If a signing key is provided via `--verify-key`, it cryptographically validates the author's signature.
- **Policy (Optional)**: If a `CapsulePolicy` is provided via `--policy`, it lints the capsule against the required algorithms, profiles, and signers.

## Usage

```sh
lvau-cli preflight --in-file secrets.lvau
```

With signature and policy verification:
```sh
lvau-cli preflight --in-file secrets.lvau \
    --verify-key release_team.lvau-verify \
    --policy strict.toml
```

## JSON Output for Automation

Preflight is designed to be easily consumed by CI/CD systems, pre-commit hooks, and wrapper scripts. Simply append `--json`:

```sh
lvau-cli preflight --in-file secrets.lvau --json
```

The output will be a structured JSON object detailing any warnings, policy violations, or errors encountered. If the `status` field is `"Ok"` or `"Warn"`, the capsule is generally structurally sound. If it is `"Fail"`, it should not be trusted or decrypted.
