# M-of-N Approvals

Lvau supports an M-of-N approval system to prevent unilateral decryption of sensitive capsules. This ensures that even if an attacker or a rogue employee obtains the decryption key, they cannot decrypt the capsule without additional approval seals from trusted authorities.

## How Approvals Work

1. A capsule is created with an attached `policy.toml` that sets `min_approvals = 2`.
2. The capsule is distributed to the team.
3. If an individual attempts to extract the capsule, `lvau-cli` will fail and report that it lacks the required approvals.
4. Two distinct, trusted authorities must generate an approval seal for the capsule.
5. The seals are appended to the capsule's public metadata.
6. The capsule can now be successfully extracted.

## Generating and Appending Approvals

### 1. Generate a Signing Keypair

Authorities must have their own Ed25519 signing keypairs.

```sh
lvau-cli sign-keygen --out-base manager_key
```

### 2. Approve the Capsule

An authority inspects the capsule using `preflight` or `report`, ensures its validity, and then applies their approval seal:

```sh
lvau-cli approve --in-file bundle.lvau --sign-key manager_key.lvau-sign
```

### 3. Verify Approvals

You can verify how many valid seals are attached to a capsule:

```sh
lvau-cli approvals --in-file bundle.lvau
```

Once the threshold defined in the policy is reached, the capsule becomes unlockable.
