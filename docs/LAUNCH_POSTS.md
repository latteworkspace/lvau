# Launch Posts

Draft copy for Lvau v0.1.0.

## X / Twitter

```text
I built Lvau: boring, inspectable file encryption in Rust.

It uses standard primitives, safe defaults, and a versioned .lvau envelope you can inspect without decrypting the payload.

CLI-first, GUI-supported, local-first. v0.1.0 is experimental and not audited yet.

https://github.com/latteworkspace/lvau
```

## Hacker News / Reddit

### Title

Lvau: boring, inspectable file encryption in Rust

### Body

```text
I built Lvau, a local file encryption toolkit in Rust. v0.1.0 is the first public release candidate.

What it does:
- Encrypts individual files with a password or experimental hybrid keypair
- Uses XChaCha20-Poly1305 and Argon2id in the default password path
- Writes a versioned .lvau envelope with inspectable public metadata
- Provides a CLI first, plus a native egui GUI
- Ships release binaries for Linux, Windows, and macOS

What it is not:
- Not a replacement claim against age, VeraCrypt, Cryptomator, or rclone crypt
- Not formally audited
- Not format-stable before v1.0

I would especially appreciate feedback on the threat model, file format, CLI ergonomics, and tests.

GitHub: https://github.com/latteworkspace/lvau
Threat model: https://github.com/latteworkspace/lvau/blob/main/docs/THREAT_MODEL.md
Format: https://github.com/latteworkspace/lvau/blob/main/docs/FORMAT.md
```

## GitHub Release Text

```text
Lvau v0.1.0 is the first public release candidate for a Rust-based local file encryption toolkit.

This release includes a CLI, native GUI, versioned .lvau envelope, password-based encryption, experimental hybrid keypair encryption, and cross-platform binary archives.

Please read the threat model and security policy before relying on Lvau for important data. The project has not been formally audited and the format is not stable before v1.0.
```

## Japanese X / Zenn / Qiita Draft

```text
Rust製の、地味で検証しやすいファイル暗号化ツール Lvau を作っています。

標準的な暗号プリミティブ、安全寄りの既定値、復号せずに公開メタデータを確認できる .lvau エンベロープを重視しています。

v0.1.0 は実験的な初期リリースで、正式な監査はまだありません。脅威モデルや形式へのフィードバックを歓迎します。

https://github.com/latteworkspace/lvau
```
