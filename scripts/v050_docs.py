#!/usr/bin/env python3
"""Apply the v0.5.0 release documentation updates idempotently."""

from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]

CHANGELOG_SECTION = """## [0.5.0] - 2026-07-19

### Security

- Bundle pack, list, verify, and extract now process file contents with a fixed 64 KiB buffer instead of allocating the complete plaintext payload. The serialized manifest is independently capped at 16 MiB.
- Bundle extraction authenticates every manifest entry before creating any named output and writes each file through a same-directory temporary file before atomic persistence.
- Bundle packing hashes every source in a first pass and verifies size and BLAKE3 again while streaming the second pass, rejecting files that change during packing.
- Existing format-v2 cipher suites now share explicit, fixed HKDF labels, nonce derivation, and chunk-AAD helpers with known-answer tests. This refactor preserves the v2 byte construction and does not introduce format v3.

### Added

- Added an internal versioned cryptographic-suite registry that distinguishes payload encryption layers from recipient algorithms, signatures, padding, and legacy LCO obfuscation.
- Added fixed key-schedule and nonce/AAD vectors as foundations for the separately reviewed experimental format-v3 work planned for 0.6.0.
- Added JSON output schema version 1. Machine-readable commands return a top-level `schema_version`, `command`, `status`, and `data` envelope.

### Changed

- Updated all workspace crates to version 0.5.0.
- Migrated secret-string handling to `secrecy` 0.10 and X25519 handling to `x25519-dalek` 3 with the operating-system random generator feature.
- Bundle payload layout and envelope format remain compatible with existing v2 readers; v1 and v2 reads are retained.
- CLI JSON output for inspect, verify, preflight, report, and policy lint now uses the versioned envelope contract.

### Migration

- No re-encryption is required for existing v2 files. Format v1 and v2 remain readable.
- Automation consuming JSON must read command-specific fields from `data` and may use `schema_version == 1` to select the contract.
- LCO remains legacy experimental obfuscation and is not counted or described as an encryption layer.

"""

EN_CHANGES = """## 0.5.0 changes

- Directory bundles now stream file contents through a fixed 64 KiB buffer instead of collecting the complete plaintext payload in memory. The encrypted payload layout remains format-v2 compatible.
- Pack performs two-pass size/BLAKE3 validation, and extract authenticates all entries before atomically creating named outputs.
- Existing v2 HKDF labels, nonce derivation, and chunk AAD are centralized behind a versioned suite registry with fixed compatibility vectors.
- `secrecy` 0.10 and `x25519-dalek` 3 migrations are complete.
- Machine-readable inspect, verify, preflight, report, and policy-lint output uses JSON schema version 1.
- Lvau still writes envelope v2 in this release; experimental format v3 is planned separately for 0.6.0.

See [CHANGELOG.md](CHANGELOG.md), [the JSON contract](docs/JSON_OUTPUT.md), and [the roadmap](docs/ROADMAP.md) for details.

"""

JA_CHANGES = """## 0.5.0 の変更

- directory bundle は、平文 payload 全体を memory に保持せず、固定 64 KiB buffer で file content を streaming 処理します。暗号化 payload layout は format v2 と互換です。
- pack は size/BLAKE3 を2回検証し、extract はすべての entry を認証してから named output を atomic に作成します。
- 既存 v2 の HKDF label、nonce derivation、chunk AAD を versioned suite registry に集約し、互換性 vector を固定しました。
- `secrecy` 0.10 と `x25519-dalek` 3 への移行を完了しました。
- inspect、verify、preflight、report、policy lint の machine-readable output は JSON schema version 1 を使用します。
- この release も envelope v2 を書き込みます。実験的 format v3 は 0.6.0 で別途導入します。

詳細は [CHANGELOG.md](CHANGELOG.md)、[JSON contract](docs/JSON_OUTPUT.md)、[roadmap](docs/ROADMAP.md) を参照してください。

"""

RELEASE_NOTES = """# Lvau 0.5.0

Lvau 0.5.0 is a scalability and cryptographic-foundation release. It does not introduce a new encrypted-file format: new output remains envelope v2, and supported v1/v2 input remains readable.

## Highlights

- Bounded-memory directory bundles with a fixed 64 KiB content buffer.
- Two-pass source validation during packing and authenticate-before-write extraction.
- Atomic per-file bundle extraction with no partial named plaintext outputs on failure.
- Versioned payload-suite registry and compatibility-fixed HKDF, nonce, and AAD helpers.
- `secrecy` 0.10 and `x25519-dalek` 3 dependency migrations.
- JSON output schema version 1 for automation-facing commands.

## Compatibility

The bundle payload layout and envelope-v2 cryptographic construction are unchanged. Existing format-v1 and format-v2 capsules remain readable. LCO remains legacy experimental obfuscation and is not treated as an encryption layer.

## Security status

Lvau remains unaudited and pre-1.0. This release should not be described as formally audited, unbreakable, military-grade, or suitable for protecting critical data without independent evaluation.
"""

JSON_DOC = """# CLI JSON output contract

Lvau 0.5.0 introduces JSON schema version 1 for automation-facing commands.

Successful output has this top-level shape:

```json
{
  "schema_version": 1,
  "command": "inspect",
  "status": "ok",
  "data": {}
}
```

Error documents use `status: "error"` and an `error` object containing stable `code` and human-readable `message` fields. Existing process exit codes remain authoritative for success or failure.

The generic schema is stored at `schemas/lvau-cli-output-v1.schema.json`. Fields inside `data` are command-specific. New fields may be added compatibly within schema version 1, while removal or semantic reinterpretation requires a new schema version.
"""


def insert_before(path: pathlib.Path, marker: str, section: str) -> None:
    text = path.read_text(encoding="utf-8")
    if section.splitlines()[0] not in text:
        text = text.replace(marker, section + marker, 1)
    path.write_text(text, encoding="utf-8")


changelog = ROOT / "CHANGELOG.md"
insert_before(changelog, "## [0.4.0]", CHANGELOG_SECTION)

readme = ROOT / "README.md"
text = readme.read_text(encoding="utf-8")
text = text.replace("current release is **0.4.0**", "current release is **0.5.0**")
if "## 0.5.0 changes" not in text:
    text = text.replace("## 0.4.0 changes", EN_CHANGES + "## 0.4.0 changes", 1)
readme.write_text(text, encoding="utf-8")

readme_ja = ROOT / "README_ja.md"
text = readme_ja.read_text(encoding="utf-8")
text = text.replace("現在のリリースは **0.4.0**", "現在のリリースは **0.5.0**")
if "## 0.5.0 の変更" not in text:
    text = text.replace("## 0.4.0 の変更", JA_CHANGES + "## 0.4.0 の変更", 1)
readme_ja.write_text(text, encoding="utf-8")

(ROOT / "docs/RELEASE_NOTES.md").write_text(RELEASE_NOTES, encoding="utf-8")
(ROOT / "docs/JSON_OUTPUT.md").write_text(JSON_DOC, encoding="utf-8")

threat = ROOT / "docs/THREAT_MODEL.md"
text = threat.read_text(encoding="utf-8")
text = text.replace(
    "- Bundle operations currently buffer the complete decrypted bundle. A local\n  filesystem race can still occur between path validation and creation; use a\n  fresh destination owned by the decrypting user.",
    "- Bundle file contents use bounded streaming buffers, but the authenticated\n  manifest is held in memory up to the documented 16 MiB limit. A local filesystem\n  race can still occur while creating parent directories; use a fresh destination\n  owned by the decrypting user.",
)
threat.write_text(text, encoding="utf-8")
