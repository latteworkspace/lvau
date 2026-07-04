# Capsule Policy

Lvau v0.4.0 introduces the concept of a **Capsule Policy**. This allows organizations and individuals to define minimum security requirements for their encrypted `.lvau` capsules, ensuring that weak encryption is rejected *before* decryption is attempted.

## The Problem

By default, an encryption tool will gladly decrypt whatever you give it, as long as you have the right key. However, this means a user might unknowingly accept and rely on an encrypted file that used the `fast` KDF profile, an outdated cipher, or lacked a required author signature.

## The Solution: TOML Policies

Lvau uses a `CapsulePolicy` (typically stored as `policy.toml`) to enforce security invariants on the public envelope metadata.

### Example `policy.toml`

```toml
[policy]
# The minimum allowed version of the Lvau envelope format
min_version = 1

# List of allowed algorithms (others will be rejected)
allowed_algorithms = [
    "XChaCha20Poly1305",
    "XChaCha20Poly1305_Argon2id"
]

# List of allowed KDF profiles
allowed_profiles = [
    "Balanced",
    "Archive",
    "Paranoid"
]

# Ensure that the capsule was signed by at least one of these Ed25519 keys
required_signers = [
    "d23a1b4c...f910a", # Alice
    "a19f8b4c...0c91b"  # Release Engineering Key
]
```

## How to use a Policy

You can provide a policy file to almost any `lvau-cli` command:

**Encryption:**
If you pass `--policy policy.toml` during encryption, Lvau will ensure the parameters you've chosen meet the policy requirements before generating the capsule. (You can bypass this with `--allow-policy-override`, which sets a flag in the metadata).

```sh
lvau-cli encrypt --in-file data.txt --out-file data.lvau --policy strict-policy.toml
```

**Preflight & Decryption:**
If you pass `--policy policy.toml` during decryption or preflight, Lvau will verify the capsule against the policy *before* asking for a password or attempting to decrypt.

```sh
lvau-cli preflight --in-file data.lvau --policy strict-policy.toml
```

If the policy fails, Lvau will abort with a detailed error message indicating which constraints were violated.
