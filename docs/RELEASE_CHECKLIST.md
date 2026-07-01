# Release Checklist

Use this checklist before publishing a new Lvau release.

## Pre-release

- [ ] All CI checks pass (fmt, clippy, test, build)
- [ ] `CHANGELOG.md` updated with release date and changes
- [ ] Version numbers updated in all `Cargo.toml` files
- [ ] README examples verified against actual CLI behavior
- [ ] No broken markdown links

## Testing

- [ ] Roundtrip encryption/decryption test passes (`cargo test`)
- [ ] Wrong password test passes
- [ ] Tampered/corrupted file test passes
- [ ] Cascade profile (paranoid) roundtrip test passes
- [ ] Manual CLI roundtrip on local machine:
  ```sh
  echo "test data" > test_input.txt
  lvau-cli encrypt --in-file test_input.txt --out-file test.lvau --password --profile balanced
  lvau-cli inspect --in-file test.lvau
  lvau-cli decrypt --in-file test.lvau --out-file test_output.txt --password
  diff test_input.txt test_output.txt  # or: fc test_input.txt test_output.txt (Windows)
  ```
- [ ] Large file test (if supported — test with a 100+ MB file)
- [ ] GUI manual test: encrypt and decrypt via `lvau-gui`

## Build

- [ ] `cargo build --release` succeeds locally
- [ ] Cross-platform builds verified via GitHub Actions release workflow:
  - [ ] Linux x86_64
  - [ ] Windows x86_64
  - [ ] macOS x86_64
  - [ ] macOS aarch64

## Release

- [ ] Create and push a git tag:
  ```sh
  git tag -a v0.1.0 -m "v0.1.0 — Boring, inspectable file encryption"
  git push origin v0.1.0
  ```
- [ ] GitHub Actions release workflow triggers and completes
- [ ] GitHub Release created with:
  - [ ] Binary archives for all platforms
  - [ ] `checksums.txt` with SHA-256 hashes
  - [ ] Release notes (from `docs/V0_1_0_RELEASE_NOTES_DRAFT.md` or similar)
- [ ] Download and verify at least one binary from the release
- [ ] Verify checksum matches

## Post-release

- [ ] Update `CHANGELOG.md` with release date
- [ ] Announce on relevant channels (see `docs/LAUNCH_POSTS.md`)
- [ ] crates.io publish (if applicable — currently `publish = false` on all crates)
- [ ] Monitor for issue reports
