# Preflight Inspections

A core feature of Lvau is the ability to inspect and verify an encrypted capsule *without* having the decryption password or private key.

## `lvau-cli preflight`

The `preflight` command analyzes the public envelope of a capsule and generates a security report.

```sh
lvau-cli preflight --in-file mybundle.lvau
```

### What it checks

1. **Version Compatibility**: Ensures your version of Lvau can parse the capsule.
2. **Security Profile**: Extracts the KDF profile and cryptographic algorithm used.
3. **Public Hash Integrity**: Verifies that the public manifest has not been tampered with.
4. **Signature Status**: Checks for the presence of an author signature.
5. **Metadata Presence**: Detects if recovery shares or release metadata are attached.
6. **Policy Overrides**: Determines if the author forced policy overrides during encryption.

### Preflight vs Inspect

- `lvau-cli inspect` simply dumps the raw JSON or human-readable data from the capsule manifest.
- `lvau-cli preflight` acts as a **doctor** for the capsule, actively analyzing the parameters to provide `Warn`, `Pass`, or `Fail` signals based on modern security standards.
