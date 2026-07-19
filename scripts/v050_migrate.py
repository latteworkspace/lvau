#!/usr/bin/env python3
"""Apply the mechanical source migrations required by the v0.5.0 branch.

This script is intentionally idempotent. It handles only API-shape and module
wiring changes; cryptographic behavior changes belong in reviewed Rust code.
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


def update_manifests() -> None:
    for path in ROOT.joinpath("crates").glob("*/Cargo.toml"):
        text = path.read_text(encoding="utf-8")
        text = re.sub(r'(?m)^version = "0\.4\.0"$', 'version = "0.5.0"', text, count=1)
        if path.name == "Cargo.toml" and path.parent.name == "lvau-core":
            text = text.replace(
                'x25519-dalek = { version = "3.0.0", features = ["static_secrets"] }',
                'x25519-dalek = { version = "3.0.0", features = ["static_secrets", "getrandom"] }',
            )
        path.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    migrate_rust_sources()
    wire_crypto_modules()
    update_manifests()
