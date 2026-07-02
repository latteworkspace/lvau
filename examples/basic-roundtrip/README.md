# Basic Roundtrip Example

This example encrypts a sample file, inspects the `.lvau` envelope, decrypts it, and compares hashes.

## Run The Script

Build Lvau first or point `LVAU_CLI` at a downloaded binary.

```sh
cargo build --release --package lvau-cli
LVAU_CLI=../../target/release/lvau-cli ./run.sh
```

PowerShell:

```powershell
cargo build --release --package lvau-cli
$env:LVAU_CLI = "..\..\target\release\lvau-cli.exe"
.\run.ps1
```

The scripts use a temporary directory and remove it when they finish.

## Manual Steps

Create a sample file and a local password file:

```sh
echo "Hello, Lvau!" > sample.txt
echo "correct horse battery staple" > password.txt
```

Encrypt:

```sh
lvau-cli encrypt --in-file sample.txt --out-file sample.lvau --password-file password.txt --profile fast
```

Inspect without decrypting:

```sh
lvau-cli inspect --in-file sample.lvau
```

Decrypt:

```sh
lvau-cli decrypt --in-file sample.lvau --out-file sample.decrypted.txt --password-file password.txt
```

Compare hashes:

```sh
sha256sum sample.txt sample.decrypted.txt
```

PowerShell:

```powershell
Get-FileHash sample.txt -Algorithm SHA256
Get-FileHash sample.decrypted.txt -Algorithm SHA256
```
