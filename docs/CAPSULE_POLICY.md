# Capsule Policy

A capsule policy is a local TOML lint configuration. It checks public envelope
properties before decryption and can be applied while packing a bundle. It is
not embedded authorization logic and is not automatically enforced by
`decrypt` or `bundle extract`.

## Commands

```sh
lvau-cli policy create --out-file policy.toml
lvau-cli policy inspect --in-file policy.toml
lvau-cli policy lint --in-file bundle.lvau --policy policy.toml
lvau-cli preflight --in-file bundle.lvau --policy policy.toml --json
lvau-cli bundle pack \
  --in-dir input \
  --out-file bundle.lvau \
  --password \
  --policy policy.toml
```

`bundle pack` fails on a violation unless
`--allow-policy-override` is explicitly used. In v2 that override flag is part
of the payload commitment. Extraction does not accept a `--policy` option; run
`policy lint` or `preflight` as a separate workflow step if local policy must
pass first.

## Rules

| TOML field | Current check |
| --- | --- |
| `require_signature` | Requires a stored author-signature record; verification needs `--verify-key`. |
| `require_recovery` | Requires recovery metadata to be present; share availability is not verified. |
| `min_kdf_profile` | Checks Argon2id costs for password capsules. It is not applicable when no password KDF exists. |
| `allowed_ciphers` | Allows named payload algorithms. |
| `allowed_kdfs` | Allows `Argon2id` or `None`. |
| `allow_lco` | Rejects the LCO payload algorithm when false. |
| `allow_experimental` | Rejects cascade/LCO profiles and hybrid key-pair recipients when false. |
| `require_recipient_count_min` | Counts public recipient slots. |
| `require_approval_signatures_min` | Counts distinct stored approval fingerprints, without proving validity or trust. |
| `public_label_allowed` | Rejects a public label when false. |
| `created_by_required` | Requires public project metadata; identity still requires a trusted signature. |
| `require_metadata_profile` | Fails closed: the encrypted bundle property cannot be proved by public lint. |
| `require_padding` | Fails closed: the current envelope does not authenticate the selected padding policy as a public field. |

The accepted `min_kdf_profile` values are `interactive`, `moderate`, and
`strong`. Cipher names match the Rust enum spellings shown by `inspect`.

## Trust boundary

Anyone who can rewrite an unsigned capsule can also rewrite public records and
recompute an unkeyed public hash. Presence checks are therefore only structural
signals. Use `verify-signature`/`preflight --verify-key` with an independently
trusted Ed25519 public key when author authenticity matters, and verify every
required approval key separately.

Policy files are local inputs. Protect the policy and the automation that
selects it; accepting an attacker-supplied policy defeats the purpose.
