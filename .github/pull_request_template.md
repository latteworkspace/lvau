## Summary

Describe the change and why it is needed.

## Checklist

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test --workspace --all-features`
- [ ] `cargo build --workspace --release`
- [ ] Documentation updated, if commands, formats, workflows, or security wording changed
- [ ] Security-sensitive changes include tests and conservative wording

## Security Notes

Does this change touch crypto, KDF parameters, nonce handling, key files, envelope parsing, or release artifacts?
