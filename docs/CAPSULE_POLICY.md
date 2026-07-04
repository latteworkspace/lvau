# Capsule Policy

Lvau introduces a strict policy engine designed to ensure that encrypted capsules comply with your organization's security standards *before* anyone attempts to decrypt them.

## Policy Rules

A Lvau capsule policy (`policy.toml`) can enforce the following rules:

1. **`require_signature`**: The capsule MUST be signed by a trusted Ed25519 author key.
2. **`allow_experimental`**: If false, the capsule MUST NOT use experimental features (like LCO obfuscation or SFX wrappers).
3. **`min_kdf_profile`**: Ensures the capsule uses a sufficiently strong Key Derivation Function (e.g., `Balanced`, `Paranoid`). Weak capsules will be rejected.
4. **`min_approvals`**: Requires the capsule to have at least `N` distinct approval seals before it can be extracted.

## Managing Policies

### Create a Policy

```sh
lvau-cli policy create --out-file secure_policy.toml
```

This creates a default policy file. You can edit it manually to match your requirements.

### Lint a Capsule Against a Policy

```sh
lvau-cli policy lint --in-file bundle.lvau --policy secure_policy.toml
```

This will run the policy engine against the public manifest of the capsule. It will return a `PASS` or `FAIL` with a detailed list of policy violations.

## Integration

Capsule Policies are integrated into extraction and preflight checks. By providing a `--policy` argument to `lvau-cli bundle extract`, Lvau will outright refuse to decrypt a capsule that violates the policy, protecting your system from maliciously downgraded crypto parameters or unsigned payloads.
