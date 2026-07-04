# Differentiation

Lvau is designed to fill a specific gap in the local encryption ecosystem. While excellent tools already exist, they are often designed for very different use cases.

## Why not age?

[age](https://github.com/FiloSottile/age) is a simple, modern, and secure file encryption tool.

**Lvau vs age:**
- `age` is designed for pure Unix philosophy: stdin to stdout stream encryption.
- Lvau is designed for **structured capsules**. A Lvau capsule contains an authenticated manifest, author signatures, release metadata, and recipient groups.
- Lvau explicitly avoids being "just another stream cipher." Instead, it acts as a smart container for secrets and bundles that can be verified and managed *without* decrypting the payload first.

## Why not VeraCrypt?

VeraCrypt creates virtual encrypted disks within a file and mounts them as real disks.

**Lvau vs VeraCrypt:**
- VeraCrypt provides real-time, transparent file system access (perfect for full-disk encryption or massive active archives).
- Lvau is an **artifact processor**. You seal files and directories into a single `.lvau` file for safe transport, git storage, or automated pipelines. Lvau does not require system privileges or drivers to mount filesystems.

## Why not Cryptomator?

Cryptomator provides transparent client-side encryption for your cloud files.

**Lvau vs Cryptomator:**
- Cryptomator encrypts each file individually to allow transparent syncing via Dropbox, Google Drive, etc.
- Lvau treats directories as **sealed bundles**. The bundle is atomic and signed, preventing attackers from modifying individual files or metadata unnoticed.

## Why not SOPS?

SOPS is an editor of encrypted files that supports YAML, JSON, ENV, INI, and BINARY formats.

**Lvau vs SOPS:**
- SOPS is built heavily around cloud KMS (AWS KMS, GCP KMS, Azure Key Vault) and PGP.
- Lvau is designed for **local-first developers** and CI/CD environments. It provides native CLI secrets management (`lvau-cli secret`) without depending on external cloud providers, and uses modern, post-quantum ready cryptography (X25519 + ML-KEM-768) rather than PGP.
- Lvau includes strict **Capsule Policies**, ensuring that secrets cannot be modified by individuals without satisfying M-of-N multi-signature approvals.
