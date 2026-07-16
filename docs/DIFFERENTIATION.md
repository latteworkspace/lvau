# Positioning and Alternatives

Lvau is a local-first, experimental encrypted-artifact tool. Its current focus
is a self-describing `.lvau` capsule, single files and sealed directory
bundles, public preflight inspection, optional author/approval attestations,
and CLI/GUI workflows built on the same Rust core.

It is not automatically safer than mature alternatives, and its format is not
an interoperability standard. Choose based on the workflow and threat model:

| Need | Usually evaluate first | Where Lvau differs |
| --- | --- | --- |
| Small, interoperable file encryption and Unix pipelines | [age](https://age-encryption.org/) | Lvau uses its own versioned capsule and richer public workflow metadata. |
| Mounted encrypted containers or disks | [VeraCrypt](https://www.veracrypt.fr/) | Lvau produces artifacts; it does not mount a filesystem. |
| Transparent encrypted cloud-folder synchronization | [Cryptomator](https://cryptomator.org/) | Lvau seals a file or bundle rather than presenting a sync-oriented virtual drive. |
| Editing structured configuration with cloud/key-service integrations | [SOPS](https://getsops.io/) | Lvau's structured-secret commands encrypt the whole local file and do not currently offer SOPS-style per-value or KMS workflows. |

Lvau-specific capabilities should be read with these limits:

- “inspectable” means selected envelope metadata is public; it does not mean
  unsigned metadata is trusted;
- signatures and approvals require independently trusted verification keys;
- approval count is advisory and does not enforce M-of-N decryption;
- hybrid X25519 + ML-KEM-768, cascade profiles, LCO, recovery, SFX, and GUI
  workflows are experimental; and
- the project has not undergone a formal independent security audit.

For long-lived or high-impact data, compare the operational maturity,
interoperability, audit history, recovery model, and update channel of every
candidate—not just its primitive list.
