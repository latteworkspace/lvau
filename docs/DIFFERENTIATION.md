# Differentiation

Lvau is an encrypted capsule toolkit designed specifically for local files and developer workflows. It is not trying to compete with or replace established encryption tools. Instead, it offers a specific combination of features that are useful for managing signed, policy-checked, recoverable encrypted artifacts.

## What is a Capsule?

Unlike a standard encrypted file, a Lvau **capsule** (`.lvau`) contains more than just ciphertext. It can include:
- An encrypted payload (single file or a directory bundle)
- An encrypted private manifest (for bundles)
- Minimal public metadata (version, profile, algorithm, KDF parameters)
- Multiple recipient slots (passwords or keypairs)
- Public release metadata (project name, version, commit hash, build timestamp)
- Recovery metadata slots
- An author signature
- Post-encryption approval seals

This makes the capsule self-describing, verifiable, and policy-checkable without needing the decryption password.

## When to use other tools

**Age**
Use [age](https://github.com/FiloSottile/age) if you need a simple, audited, and widely-trusted file encryption tool. `age` is the gold standard for simple file encryption. Lvau does not claim to be more secure than `age`.

**VeraCrypt**
Use [VeraCrypt](https://www.veracrypt.fr/) if you need full-disk encryption, plausible deniability, or hidden encrypted volumes. Lvau does not provide plausible deniability.

**Cryptomator**
Use [Cryptomator](https://cryptomator.org/) if you need transparent, cloud-synced encrypted vaults. Cryptomator integrates directly with file explorers, whereas Lvau is an explicit pack/unpack tool.

**SOPS**
Use [SOPS](https://github.com/getsops/sops) if you need to encrypt specific values within JSON/YAML configuration files for GitOps workflows. Lvau encrypts entire files/directories, not just values within structured files (though structured secrets are planned for future releases).

## When to use Lvau

- **Sealed Directory Bundles**: You want to encrypt a folder containing multiple files (like project secrets) into a single, verifiable artifact.
- **Signed Provenance**: You want to prove who created an encrypted backup without revealing the decryption password.
- **Preflight Checks & Policies**: You want to enforce that all encrypted artifacts in your organization use the `paranoid` profile and are signed by an approved key *before* anyone attempts to decrypt them.
- **Approval Seals**: You want a CI/CD pipeline to add a cryptographic "seal of approval" to an existing encrypted artifact, without ever possessing the decryption key.
- **Recipient Groups**: You want to easily encrypt a file for multiple team members using a shared `group.toml` file.
- **Recovery Integration**: You want a tool that can attach offline recovery metadata (like Shamir shares) directly to the encrypted file's public header for emergency access by administrators.

Lvau is honest, boring, testable, and built on standard cryptographic primitives (XChaCha20-Poly1305, Argon2id, Ed25519). It doesn't claim "military grade" security, and it doesn't invent custom ciphers. It simply combines reliable cryptography with a capsule architecture that serves developer and operational workflows.
