#!/usr/bin/env python3
"""Apply compiler and test corrections identified by final CI."""

from pathlib import Path

root = Path(__file__).resolve().parents[1]

crypto = root / "crates/lvau-core/src/crypto/mod.rs"
text = crypto.read_text(encoding="utf-8")
text = text.replace(
    "key_schedule::derive_subkey(&kw_hk, key_schedule::KeyPurpose::KeyWrap, &mut *kwk)?;",
    "key_schedule::derive_subkey(&kw_hk, key_schedule::KeyPurpose::KeyWrap, &mut kwk)?;",
)
crypto.write_text(text, encoding="utf-8")

cli_test = root / "crates/lvau-cli/tests/cli.rs"
text = cli_test.read_text(encoding="utf-8")
text = text.replace(
    '''    assert_eq!(parsed["magic"], "LVAU");
    assert_eq!(parsed["signed"], false);''',
    '''    assert_eq!(parsed["schema_version"], 1);
    assert_eq!(parsed["command"], "inspect");
    assert_eq!(parsed["status"], "ok");
    assert_eq!(parsed["data"]["magic"], "LVAU");
    assert_eq!(parsed["data"]["signed"], false);''',
)
cli_test.write_text(text, encoding="utf-8")

bundle_stream = root / "crates/lvau-core/src/bundle_stream.rs"
text = bundle_stream.read_text(encoding="utf-8")
text = text.replace(
    '''        assert_eq!(BUNDLE_COPY_BUFFER_SIZE, 64 * 1024);
        assert!(BUNDLE_COPY_BUFFER_SIZE < 1024 * 1024);''',
    '''        assert_eq!(BUNDLE_COPY_BUFFER_SIZE, 64 * 1024);''',
)
bundle_stream.write_text(text, encoding="utf-8")
