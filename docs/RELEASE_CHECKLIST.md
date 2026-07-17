# Release Checklist

Only a maintainer with explicit authorization may create or push a release tag.
The tag workflow publishes a GitHub Release automatically, so a tag is a
production action—not a harmless test. There is intentionally no manual
`workflow_dispatch` release path.

## 1. Establish the candidate

- [ ] Choose the SemVer from actual CLI/API/format/config changes.
- [ ] Set every workspace crate to the same version.
- [ ] Add an accurate, dated `CHANGELOG.md` section.
- [ ] Update `docs/RELEASE_NOTES.md` without renaming it to a version-specific
      path.
- [ ] Update `README.md`, `README_ja.md`, `docs/FORMAT.md`, roadmap, site release
      metadata, and migration notes together.
- [ ] Confirm no old owner URL, stale version, unsupported security claim, or
      secret is present.
- [ ] Review RustSec findings and every time-bounded audit exception.

## 2. Verify from WSL2 / Ubuntu 26.04

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
cargo build --locked --workspace --release
cargo tree --duplicates
cargo run --locked --quiet --package lvau-cli -- self-test
cargo audit
```

- [ ] Run wrong-password/key, corrupt/truncated/oversized-envelope, legacy-read,
      bundle traversal/symlink, JSON-output, and recovery tests.
- [ ] Run the website tests, lint, typecheck, and production build.
- [ ] Run API fmt, Clippy, tests, release build, and `shellcheck` for deploy
      scripts.
- [ ] Statically parse all workflow YAML. Run `actionlint` when available.
- [ ] Review Windows/macOS CI results; local WSL success is not cross-platform
      proof.

## 3. Manual CLI smoke test

```sh
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
printf 'test data\n' > "$tmpdir/input.txt"
printf 'local-smoke-test-password\n' > "$tmpdir/password.txt"
chmod 600 "$tmpdir/password.txt"

target/release/lvau-cli encrypt \
  --in-file "$tmpdir/input.txt" \
  --out-file "$tmpdir/input.lvau" \
  --password-file "$tmpdir/password.txt" \
  --profile fast
target/release/lvau-cli inspect --in-file "$tmpdir/input.lvau" --json
target/release/lvau-cli verify \
  --in-file "$tmpdir/input.lvau" \
  --password-file "$tmpdir/password.txt" \
  --json
target/release/lvau-cli decrypt \
  --in-file "$tmpdir/input.lvau" \
  --out-file "$tmpdir/output.txt" \
  --password-file "$tmpdir/password.txt"
cmp "$tmpdir/input.txt" "$tmpdir/output.txt"
```

Also inspect `--help` and exercise GUI encrypt/decrypt on each supported desktop
before declaring GUI assets ready.

## 4. Authorized tag workflow

- [ ] Obtain explicit approval for the exact commit and tag.
- [ ] Confirm the tag is `v<workspace-version>` and points to the reviewed
      commit.
- [ ] Push the tag only after branch CI is green.
- [ ] Confirm the workflow validates tag, crate versions, changelog, fmt,
      Clippy, tests, self-test, and CLI roundtrip.
- [ ] Confirm all target builds succeeded:
  - `lvau-x86_64-unknown-linux-gnu.tar.gz`
  - `lvau-x86_64-pc-windows-msvc.zip`
  - `lvau-x86_64-apple-darwin.tar.gz`
  - `lvau-aarch64-apple-darwin.tar.gz`
- [ ] Confirm `checksums.txt` and per-crate `*.cdx.json` CycloneDX SBOMs exist.
- [ ] Verify the GitHub artifact attestation covers archives, checksums, and
      SBOMs.
- [ ] Download each archive, validate its checksum, inspect its contents, and
      run `lvau-cli --version`, `--help`, `self-test`, and a roundtrip on native
      hardware where practical.
- [ ] Confirm prerelease tags are marked as prereleases and release notes match
      the tag.

## 5. Post-release

- [ ] Verify website download links, filenames, architectures, checksum
      instructions, canonical URL, and release version.
- [ ] Keep rollback/migration guidance available for v1 capsules and API/site
      deployments.
- [ ] Record any unverified platform or operational check; do not infer success
      from another platform.
