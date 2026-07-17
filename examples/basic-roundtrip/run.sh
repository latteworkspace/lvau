#!/usr/bin/env sh
set -eu

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

BIN="${LVAU_CLI:-lvau-cli}"

printf '%s\n' 'Hello, Lvau! This file should survive encryption and decryption.' > "$WORKDIR/sample.txt"
printf '%s\n' 'correct horse battery staple' > "$WORKDIR/password.txt"
chmod 600 "$WORKDIR/password.txt"

"$BIN" encrypt \
  --in-file "$WORKDIR/sample.txt" \
  --out-file "$WORKDIR/sample.lvau" \
  --password-file "$WORKDIR/password.txt" \
  --profile fast

"$BIN" inspect --in-file "$WORKDIR/sample.lvau"

"$BIN" decrypt \
  --in-file "$WORKDIR/sample.lvau" \
  --out-file "$WORKDIR/sample.decrypted.txt" \
  --password-file "$WORKDIR/password.txt"

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$WORKDIR/sample.txt" "$WORKDIR/sample.decrypted.txt"
fi

cmp "$WORKDIR/sample.txt" "$WORKDIR/sample.decrypted.txt"
printf '%s\n' 'Roundtrip succeeded.'
