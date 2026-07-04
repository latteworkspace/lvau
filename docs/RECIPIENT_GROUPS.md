# Recipient Groups

When using Lvau's experimental hybrid keypair encryption (X25519 + ML-KEM-768), you can encrypt a file so that multiple different people can decrypt it using their own private keys.

To make managing multiple public keys easier, Lvau supports **Recipient Groups** via TOML configuration files.

## Creating a Group

You can define a group of recipients in a `group.toml` file. This file simply lists the paths to each recipient's public key (`.lvau-pub`).

```toml
name = "infrastructure-team"
description = "Keys for the core infrastructure team"

[[recipients]]
name = "alice"
key_path = "keys/alice.lvau-pub"

[[recipients]]
name = "bob"
key_path = "keys/bob.lvau-pub"

[[recipients]]
name = "charlie"
key_path = "keys/charlie.lvau-pub"
```

## Using a Group

When encrypting a file or packing a bundle, you can pass the recipient group file using the `--recipient-group` flag:

```sh
lvau-cli encrypt --in-file secret.txt \
    --out-file secret.lvau \
    --recipient-group infrastructure-team.toml
```

Lvau will read the group file, load all the referenced public keys, and create a recipient slot in the `.lvau` capsule for each key. Any member of the group can then decrypt the file using their own private key:

```sh
# Alice decrypts the file
lvau-cli decrypt --in-file secret.lvau \
    --out-file secret.restored.txt \
    --priv-key keys/alice.lvau-key
```

## Tooling

Lvau provides built-in commands to help manage these TOML files without hand-editing them.

```sh
# Create a new empty group
lvau-cli recipients group create --out-file team.toml --name "My Team"

# Add a public key to the group
lvau-cli recipients group add --group-file team.toml --pub-key alice.lvau-pub --name "alice"

# List members in a group
lvau-cli recipients group list --group-file team.toml

# Remove a member from the group
lvau-cli recipients group remove --group-file team.toml --name "alice"
```
