# Release Checklist

Use this checklist before publishing Lvau.

## Pre-release

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test --workspace --all-features`
- [ ] `cargo build --workspace --release`
- [ ] `CHANGELOG.md` has the release date and accurate changes
- [ ] All `Cargo.toml` versions match the release
- [ ] README commands match `lvau-cli --help`
- [ ] `README.md` and `README_ja.md` describe the same behavior
- [ ] `docs/FORMAT.md` matches the code
- [ ] No unsupported security claims are present

## Manual CLI Smoke Test

```sh
tmpdir="$(mktemp -d)"
printf 'test data\n' > "$tmpdir/input.txt"
printf 'correct horse battery staple\n' > "$tmpdir/password.txt"
target/release/lvau-cli encrypt --in-file "$tmpdir/input.txt" --out-file "$tmpdir/input.lvau" --password-file "$tmpdir/password.txt" --profile fast
target/release/lvau-cli inspect --in-file "$tmpdir/input.lvau"
target/release/lvau-cli decrypt --in-file "$tmpdir/input.lvau" --out-file "$tmpdir/output.txt" --password-file "$tmpdir/password.txt"
cmp "$tmpdir/input.txt" "$tmpdir/output.txt"
```

PowerShell:

```powershell
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
"test data" | Set-Content -Path (Join-Path $tmp "input.txt")
"correct horse battery staple" | Set-Content -Path (Join-Path $tmp "password.txt")
target\release\lvau-cli.exe encrypt --in-file (Join-Path $tmp "input.txt") --out-file (Join-Path $tmp "input.lvau") --password-file (Join-Path $tmp "password.txt") --profile fast
target\release\lvau-cli.exe inspect --in-file (Join-Path $tmp "input.lvau")
target\release\lvau-cli.exe decrypt --in-file (Join-Path $tmp "input.lvau") --out-file (Join-Path $tmp "output.txt") --password-file (Join-Path $tmp "password.txt")
Compare-Object (Get-Content (Join-Path $tmp "input.txt")) (Get-Content (Join-Path $tmp "output.txt"))
```

## Release Workflow

- [ ] Push a tag like `v0.1.0`
- [ ] `.github/workflows/release.yml` completes
- [ ] Assets exist:
  - [ ] `lvau-x86_64-unknown-linux-gnu.tar.gz`
  - [ ] `lvau-x86_64-pc-windows-msvc.zip`
  - [ ] `lvau-x86_64-apple-darwin.tar.gz`
  - [ ] `lvau-aarch64-apple-darwin.tar.gz`
  - [ ] `checksums.txt`
- [ ] Download at least one asset and verify `lvau-cli --help`
- [ ] Verify checksums

## Publish

```sh
git tag v0.1.0
git push origin v0.1.0
```

Do not tag until CI and the release workflow are ready.
