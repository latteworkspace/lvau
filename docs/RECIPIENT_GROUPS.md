# Recipient Groups

Recipient Groups allow you to encrypt a Lvau capsule so that it can be decrypted by **any** member of a predefined group, without sharing a single password.

Lvau achieves this using Hybrid Keypair Encryption (X25519 + ML-KEM-768). The payload's File Encryption Key (FEK) is encrypted individually for each recipient's public key and stored in the capsule's public envelope.

## Managing Recipient Groups

A Recipient Group is stored locally as a simple TOML configuration file (e.g., `devops-team.toml`).

### 1. Create a Group

```sh
lvau-cli recipients group create devops-team.toml
```

### 2. Add Members

Each member must first generate their own hybrid keypair using `lvau-cli keygen`.

```sh
# Alice generates her key
lvau-cli keygen --out-base alice_key

# Admin adds Alice's public key to the group
lvau-cli recipients group add devops-team.toml --pub-key alice_key.lvau-pub
```

### 3. Encrypt for a Group

To encrypt a file or bundle for everyone in the group:

```sh
lvau-cli bundle pack --in-dir my_secrets/ --out-file secrets.lvau --recipient-group devops-team.toml
```

### 4. Decrypting as a Member

Any member of the group can decrypt the capsule using their own private key. They do not need the group file.

```sh
lvau-cli bundle extract --in-file secrets.lvau --out-dir extracted/ --priv-key alice_key.lvau-key
```
