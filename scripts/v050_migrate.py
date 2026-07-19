#!/usr/bin/env python3
"""Apply the mechanical source migrations required by the v0.5.0 branch.

This script is intentionally idempotent. It handles API-shape and module wiring
changes; compatibility-sensitive behavior remains implemented and tested in Rust.
"""

from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]


def replace(path: pathlib.Path, substitutions: list[tuple[str, str]]) -> None:
    text = path.read_text(encoding="utf-8")
    updated = text
    for old, new in substitutions:
        updated = updated.replace(old, new)
    if updated != text:
        path.write_text(updated, encoding="utf-8")


def migrate_rust_sources() -> None:
    substitutions = [
        ("use secrecy::{ExposeSecret, Secret};", "use secrecy::{ExposeSecret, SecretString};"),
        ("use secrecy::{Secret, ExposeSecret};", "use secrecy::{ExposeSecret, SecretString};"),
        ("use secrecy::Secret;", "use secrecy::SecretString;"),
        ("Secret<String>", "SecretString"),
        ("Secret::new(", "SecretString::from("),
        ("StaticSecret::random_from_rng(&mut rng)", "StaticSecret::random()"),
        ("StaticSecret::random_from_rng(rng)", "StaticSecret::random()"),
    ]
    for path in ROOT.joinpath("crates").rglob("*.rs"):
        replace(path, substitutions)
        text = path.read_text(encoding="utf-8")
        text = re.sub(
            r'SecretString::from\(("(?:[^"\\]|\\.)*")\.into\(\)\)',
            r'SecretString::from(\1.to_string())',
            text,
        )
        path.write_text(text, encoding="utf-8")

    keys = ROOT / "crates/lvau-core/src/crypto/keys.rs"
    text = keys.read_text(encoding="utf-8")
    text = text.replace("use rand_core::OsRng;\n", "")
    text = re.sub(
        r"pub fn generate_keypair\(\) -> \(HybridPrivateKey, HybridPublicKey\) \{\n\s*let rng = OsRng;\n",
        "pub fn generate_keypair() -> (HybridPrivateKey, HybridPublicKey) {\n",
        text,
    )
    keys.write_text(text, encoding="utf-8")


def wire_crypto_modules() -> None:
    path = ROOT / "crates/lvau-core/src/crypto/mod.rs"
    text = path.read_text(encoding="utf-8")
    declarations = ["pub mod framing;", "pub mod key_schedule;", "pub mod suite;"]
    lines = text.splitlines()
    insert_at = 0
    while insert_at < len(lines) and lines[insert_at].startswith("pub mod "):
        insert_at += 1
    for declaration in reversed(declarations):
        if declaration not in lines:
            lines.insert(insert_at, declaration)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def wire_streaming_bundle() -> None:
    lib = ROOT / "crates/lvau-core/src/lib.rs"
    text = lib.read_text(encoding="utf-8")
    if "mod bundle_stream;" not in text:
        text = text.replace("pub mod bundle;\n", "pub mod bundle;\nmod bundle_stream;\n", 1)
    lib.write_text(text, encoding="utf-8")

    bundle = ROOT / "crates/lvau-core/src/bundle.rs"
    text = bundle.read_text(encoding="utf-8")
    export = (
        "pub use crate::bundle_stream::{extract_bundle, list_bundle, pack_directory, verify_bundle};\n"
    )
    if export not in text:
        marker = "use walkdir::WalkDir;\n"
        text = text.replace(marker, marker + "\n" + export, 1)

    renames = {
        "pub fn pack_directory(": "#[allow(dead_code)]\nfn legacy_pack_directory(",
        "pub fn list_bundle(": "#[allow(dead_code)]\nfn legacy_list_bundle(",
        "pub fn extract_bundle(": "#[allow(dead_code)]\nfn legacy_extract_bundle(",
        "pub fn verify_bundle(": "#[allow(dead_code)]\nfn legacy_verify_bundle(",
    }
    for original, replacement in renames.items():
        text = text.replace(original, replacement, 1)
    bundle.write_text(text, encoding="utf-8")


def update_manifests() -> None:
    for path in ROOT.joinpath("crates").glob("*/Cargo.toml"):
        text = path.read_text(encoding="utf-8")
        text = re.sub(r'(?m)^version = "0\.4\.0"$', 'version = "0.5.0"', text, count=1)
        if path.parent.name == "lvau-core":
            text = re.sub(
                r'x25519-dalek = \{ version = "3(?:\.0\.0)?", features = \["static_secrets"\] \}',
                'x25519-dalek = { version = "3", features = ["static_secrets", "getrandom"] }',
                text,
            )
        path.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    migrate_rust_sources()
    wire_crypto_modules()
    wire_streaming_bundle()
    update_manifests()
