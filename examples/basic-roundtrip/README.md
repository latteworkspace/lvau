# Basic Roundtrip Example

This example demonstrates encrypting a file, inspecting the encrypted envelope, decrypting it, and verifying the result.

## Prerequisites

- `lvau-cli` binary (build with `cargo build --release` or download from releases)

## Steps

### 1. Create a sample file

```sh
echo "Hello, Lvau! This is a test file for roundtrip encryption." > sample.txt
```

### 2. Record the original file hash

```sh
# Linux/macOS
sha256sum sample.txt

# Windows (PowerShell)
Get-FileHash sample.txt -Algorithm SHA256
```

Save this hash for later comparison.

### 3. Encrypt the file

```sh
lvau-cli encrypt --in-file sample.txt --out-file sample.lvau --password --profile balanced
```

You will be prompted to enter and confirm a password.

### 4. Inspect the encrypted envelope

```sh
lvau-cli inspect --in-file sample.lvau
```

This prints the envelope metadata (algorithm, KDF parameters, security profile) without decrypting the contents.

### 5. Decrypt the file

```sh
lvau-cli decrypt --in-file sample.lvau --out-file sample_decrypted.txt --password
```

Enter the same password used in step 3.

### 6. Verify the roundtrip

```sh
# Linux/macOS
sha256sum sample.txt sample_decrypted.txt
# Both hashes should match

# Alternative: direct comparison
diff sample.txt sample_decrypted.txt
# No output means files are identical

# Windows (PowerShell)
Get-FileHash sample.txt -Algorithm SHA256
Get-FileHash sample_decrypted.txt -Algorithm SHA256
# Compare the Hash values — they should be identical

# Alternative: direct comparison (Windows)
fc sample.txt sample_decrypted.txt
```

### 7. Clean up

```sh
rm sample.txt sample.lvau sample_decrypted.txt
```

## Expected result

- The encrypted file (`sample.lvau`) is larger than the original (AEAD overhead + envelope metadata)
- The decrypted file is byte-for-byte identical to the original
- `inspect` shows the envelope metadata without requiring the password
- Using a wrong password for decryption produces an error
