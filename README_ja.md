# Lvau

> Rustで書かれた、地味で検証しやすいローカルファイル暗号化ツール。

Lvau は、ローカルファイルを暗号化するための Rust 製ツールキットです。標準的な暗号プリミティブ、安全寄りの既定値、復号しなくても公開メタデータを確認できるバージョン付き `.lvau` エンベロープを重視しています。

[English](README.md) | Japanese

## クイックデモ

```sh
lvau-cli encrypt --in-file secret.txt --out-file secret.txt.lvau --password
lvau-cli inspect --in-file secret.txt.lvau
lvau-cli decrypt --in-file secret.txt.lvau --out-file secret.restored.txt --password
```

自動化やテストでは、パスワードをコマンド履歴に残さないためにローカルのパスワードファイルを使えます。

```sh
lvau-cli encrypt --in-file secret.txt --out-file secret.txt.lvau --password-file password.txt
```

## 主な機能

- 既定のパスワード暗号化に XChaCha20-Poly1305 AEAD を使用
- Argon2id KDF と `fast`、`balanced`、`archive`、`paranoid`、`extreme` プロファイル
- HKDF-SHA256 による鍵分離
- マジックバイト、バージョン、KDF メタデータ、nonce、認証済みヘッダーハッシュ、平文長を含む `.lvau` エンベロープ
- Rayon による 1 MiB チャンク単位の並列処理
- CLI の非表示パスワード入力と、非対話実行用の `--password-file`
- 既存出力の上書きを既定で拒否し、必要な場合だけ `--force` を使用
- `egui` ベースのネイティブ GUI

## 実験的な機能

v0.1.0 では、次の機能は実験的です。

- X25519 + ML-KEM-768 によるハイブリッド鍵ペア暗号化
- `paranoid` と `extreme` のカスケードプロファイル
- `extreme` で使われる LCO 層。LCO は難読化であり、暗号学的な安全性の境界ではありません。
- Windows 向け自己展開アーカイブ (`--sfx`)

## インストール

### リリースバイナリ

[GitHub Releases](https://github.com/lasder-ca/lvau/releases) からダウンロードできます。

| プラットフォーム | アセット |
| --- | --- |
| Linux x86_64 | `lvau-x86_64-unknown-linux-gnu.tar.gz` |
| Windows x86_64 | `lvau-x86_64-pc-windows-msvc.zip` |
| macOS x86_64 | `lvau-x86_64-apple-darwin.tar.gz` |
| macOS aarch64 | `lvau-aarch64-apple-darwin.tar.gz` |

各アーカイブには `lvau-cli`、`lvau-gui`、`lvau-stub`、`README.md`、`LICENSE` が含まれます。Windows では `.exe` が付きます。ダウンロード後はリリースの `checksums.txt` で検証してください。

### ソースからビルド

```sh
git clone https://github.com/lasder-ca/lvau.git
cd lvau
cargo build --workspace --release
```

生成物は `target/release/` に置かれます。

## CLI の使い方

```text
lvau-cli <COMMAND> [OPTIONS]

Commands:
  encrypt   Encrypt a file
  decrypt   Decrypt a file
  inspect   Inspect public envelope metadata
  keygen    Generate an experimental hybrid keypair
```

パスワードで暗号化:

```sh
lvau-cli encrypt --in-file document.pdf --out-file document.pdf.lvau --password
```

復号:

```sh
lvau-cli decrypt --in-file document.pdf.lvau --out-file document.pdf --password
```

復号せずに公開メタデータを確認:

```sh
lvau-cli inspect --in-file document.pdf.lvau
```

プロファイル指定:

```sh
lvau-cli encrypt --in-file data.bin --out-file data.bin.lvau --password --profile archive
```

| プロファイル | Argon2id メモリ | 想定用途 |
| --- | ---: | --- |
| `fast` | 16 MiB | テストや短時間のローカル処理 |
| `balanced` | 64 MiB | 既定の一般用途 |
| `archive` | 256 MiB | 低頻度のアーカイブ用途 |
| `paranoid` | 1 GiB | 実験的なカスケードプロファイル |
| `extreme` | 1 GiB | 実験的なカスケード + LCO 難読化 |

既存ファイルを置き換える場合は `--force` を付けます。指定しない場合、Lvau は上書きを拒否します。

## GUI

`lvau-gui` は、ファイル選択、パスワードまたは鍵ペアモード、プロファイル選択、ステータス表示、ログ表示を備えています。v0.1.0 では CLI の信頼性を最優先とし、GUI は補助的な位置づけです。

```sh
cargo run --release --package lvau-gui
```

## セキュリティモデル

Lvau は、ローカルファイルを保存時に暗号化するためのツールです。攻撃者が暗号化済み `.lvau` ファイルを入手しても、正しいパスワードまたは秘密鍵がなければ内容を読めないことを目指します。

Lvau は、ファイル名、ファイルシステム上のメタデータ、平文サイズのおおよその情報を隠しません。また、マルウェア、キーロガー、侵害された OS、弱いパスワード、盗まれた秘密鍵からは保護できません。

Lvau は正式な第三者監査を受けていません。機密性の高い本番用途では、age、VeraCrypt、Cryptomator、rclone crypt などの実績あるツールも検討してください。

詳しくは [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) を読んでください。

## ファイル形式

`.lvau` 形式は v1.0 までは安定ではありません。形式の詳細は [docs/FORMAT.md](docs/FORMAT.md) にあります。

## 開発

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo build --workspace --release
```

貢献方法は [CONTRIBUTING.md](CONTRIBUTING.md) を参照してください。

## セキュリティ報告

機密性の高い脆弱性を public GitHub issue に投稿しないでください。[SECURITY.md](SECURITY.md) を参照してください。

## ライセンス

MIT。詳細は [LICENSE](LICENSE) を参照してください。
