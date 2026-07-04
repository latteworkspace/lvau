# Lvau

> ローカルファイルと開発者ワークフローのための、署名・ポリシー検証・回復可能な暗号化カプセル。

Lvau は Rust 製の暗号化カプセルツールキットです。Lvau カプセルは単なる暗号化ファイルではなく、暗号化ペイロード、暗号化されたプライベートマニフェスト、最小限の公開メタデータ、作成者の署名、受信者スロット、回復ポリシー、成果物ポリシー、検証ステータス、リリース情報を格納できます。

[English](README.md) | Japanese

[![CI](https://github.com/lasder-ca/lvau/actions/workflows/ci.yml/badge.svg)](https://github.com/lasder-ca/lvau/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> **⚠️ 未監査。** Lvau は第三者によるセキュリティ監査を受けていません。[SECURITY.md](SECURITY.md) と [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) を参照してください。

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

## Lvau の特徴

Lvau は age、VeraCrypt、Cryptomator、SOPS を置き換えるものではありません。各ツールにはそれぞれ優れた用途があります。Lvau は異なる組み合わせに注力しています。

1. **カプセルアーキテクチャ** — Lvau カプセルは、暗号化ペイロード、プライベートマニフェスト、公開リリース情報、作成者の署名を格納できる `.lvau` エンベロープです。
2. **カプセルポリシー** — TOML ポリシーファイルでカプセルを検証します。暗号化や検証の前に、必要なアルゴリズム、KDF コスト、署名などを強制できます。
3. **受信者グループ** — TOML ベースの受信者グループ定義を使用して、複数人向けに暗号化します。
4. **承認シール** — ペイロードを変更したり復号パスワードを知ることなく、Ed25519 の承認署名をカプセルに追加できます。
5. **検証と差分** — パスワードなしで公開エンベロープヘッダーを読み取れます。ファイル内容を露出することなくメタデータレポートを生成したり、2つのカプセルの構造を比較（diff）したりできます。
6. **退屈な暗号** — XChaCha20-Poly1305 AEAD、Argon2id KDF、HKDF-SHA256。カスタム暗号をセキュリティ境界として使用しません。誠実な位置づけ。

### 比較表

| 機能 | Lvau | age | VeraCrypt | Cryptomator | SOPS |
| --- | :---: | :---: | :---: | :---: | :---: |
| ファイル暗号化 | ✅ | ✅ | — | — | — |
| ディレクトリバンドル | ✅ | — | — | ✅ | — |
| ディスク/コンテナ暗号化 | — | — | ✅ | — | — |
| クラウド同期 | — | — | — | ✅ | — |
| 構造化シークレット | 予定 | — | — | — | ✅ |
| カプセルポリシー / Lint | ✅ | — | — | — | — |
| 受信者グループ | ✅ | — | — | — | — |
| 署名付き成果物・承認 | ✅ | — | — | — | ✅ |
| CLI 自動化 | ✅ | ✅ | 限定的 | — | ✅ |
| GUI | ✅ | — | ✅ | ✅ | — |
| 正式監査済み | **いいえ** | **はい** | **はい** | **はい** | 場合による |
| Rust 実装 | ✅ | ✅ (Go) | C++ | Java | Go |

**正直な評価：**
- **age** はシンプルで監査済みのファイル暗号化に優れています。それだけで十分なら age を使ってください。
- **VeraCrypt** はフルディスクおよびコンテナ暗号化に優れています。
- **Cryptomator** は透過的なクラウド同期ボールトに優れています。
- **SOPS** は GitOps ワークフローでの構造化シークレット管理に優れています。
- **Lvau** は、ローカル開発者ワークフローのための暗号化カプセルツールキットです。署名され、ポリシー検証され、回復可能な暗号化成果物が必要な場合に設計されています。

## 主な機能

- 既定のパスワード暗号化に XChaCha20-Poly1305 AEAD を使用
- Argon2id KDF と `fast`、`balanced`、`archive`、`paranoid`、`extreme` プロファイル
- HKDF-SHA256 による鍵分離
- マジックバイト、バージョン、KDF メタデータ、nonce、認証済みヘッダーハッシュ、平文長を含む `.lvau` エンベロープ
- Rayon による 1 MiB チャンク単位の並列処理
- CLI の非表示パスワード入力と、非対話実行用の `--password-file`
- 既存出力の上書きを既定で拒否し、必要な場合だけ `--force` を使用
- 一時ファイル経由のアトミック出力書き込み
- inspect と verify コマンドの `--json` 出力
- `egui` ベースのネイティブ GUI

### v0.3.0 の新機能

- **シールドバンドルモード** — ディレクトリを認証済みマニフェスト付きの1つの暗号化 `.lvau` ファイルにまとめます。メタデータプライバシーとサイズパディングを設定可能。
- **署名付き来歴** — Ed25519 で暗号化成果物に署名。復号パスワードなしで作成者を検証。
- **強化されたテスト** — プロパティラウンドトリップテスト、破損エンベロープテスト、パストラバーサルテストなど。
- **`--json` 出力** — inspect と verify の機械可読出力。

## 実験的な機能

v0.3.0 では、次の機能は実験的です。

- X25519 + ML-KEM-768 によるハイブリッド鍵ペア暗号化
- `paranoid` と `extreme` のカスケードプロファイル
- `extreme` で使われる LCO 層。LCO は難読化であり、暗号学的な安全性の境界ではありません。
- Windows 向け自己展開アーカイブ (`--sfx`)

## セキュリティ警告

> **⚠️ 弱いパスワードを使わないでください。** Argon2id はブルートフォース攻撃を遅くしますが、`password123` や `1234` のようなパスワードは保護できません。最低4〜5個のランダムな単語のパスフレーズ、またはパスワードマネージャーで生成した16文字以上のパスワードを使ってください。

> **⚠️ 未監査。** 暗号設計は標準的で十分にレビューされたプリミティブを使用していますが、実装は専門家によるレビューを受けていません。機密性の高い本番用途では、age、VeraCrypt、Cryptomator などの監査済みツールも検討してください。

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
  encrypt          ファイルを暗号化
  decrypt          ファイルを復号
  inspect          復号せずに公開エンベロープメタデータを表示
  keygen           実験的ハイブリッド鍵ペアを生成
  verify           復号せずにファイル整合性を検証
  bundle           ディレクトリバンドルの作成・展開・検証
  sign-keygen      Ed25519 署名鍵ペアを生成
  sign             .lvau ファイルに署名
  verify-signature .lvau ファイルの署名を検証
  self-test        組み込み統合テストを実行
  doctor           環境診断を表示
```

### パスワードで暗号化

```sh
lvau-cli encrypt --in-file document.pdf --out-file document.pdf.lvau --password
```

### 復号

```sh
lvau-cli decrypt --in-file document.pdf.lvau --out-file document.pdf --password
```

### 復号せずに公開メタデータを確認

```sh
lvau-cli inspect --in-file document.pdf.lvau
lvau-cli inspect --in-file document.pdf.lvau --json
```

### ディレクトリをバンドル

```sh
lvau-cli bundle pack --in-dir ./project-secrets/ --out-file secrets.lvau --password
lvau-cli bundle inspect --in-file secrets.lvau
lvau-cli bundle list --in-file secrets.lvau --password
lvau-cli bundle extract --in-file secrets.lvau --out-dir ./restored/ --password
lvau-cli bundle extract --in-file secrets.lvau --out-dir ./restored/ --password --dry-run
```

### 署名と検証

```sh
lvau-cli sign-keygen --out-base maintainer
lvau-cli sign --in-file release.lvau --signing-key maintainer.lvau-sign --out-file release-signed.lvau
lvau-cli verify-signature --in-file release-signed.lvau --verify-key maintainer.lvau-verify
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

`lvau-gui` は、ファイル選択、パスワードまたは鍵ペアモード、プロファイル選択、ステータス表示、ログ表示を備えています。CLI の信頼性を最優先とし、GUI は補助的な位置づけです。

```sh
cargo run --release --package lvau-gui
```

## セキュリティモデル

Lvau は、ローカルファイルを保存時に暗号化するためのツールです。攻撃者が暗号化済み `.lvau` ファイルを入手しても、正しいパスワードまたは秘密鍵がなければ内容を読めないことを目指します。

Lvau は、ファイル名、ファイルシステム上のメタデータ、平文サイズのおおよその情報を隠しません。また、マルウェア、キーロガー、侵害された OS、弱いパスワード、盗まれた秘密鍵からは保護できません。

Lvau は正式な第三者監査を受けていません。機密性の高い本番用途では、age、VeraCrypt、Cryptomator、rclone crypt などの実績あるツールも検討してください。

詳しくは [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) を読んでください。

## ロードマップ

| バージョン | テーマ | 主な機能 |
| --- | --- | --- |
| **v0.3.0** | 検証可能・署名付き・シールド | バンドル、Ed25519 署名、テスト強化、ドキュメント刷新 |
| **v0.4.0** | ポリシー検証カプセル | カプセルポリシー、事前検証、承認シール、差分、グループ、メタデータ |
| **v1.0** | 安定フォーマット | フォーマット凍結、正式監査目標、安定 API |

詳細は [docs/ROADMAP.md](docs/ROADMAP.md) を参照してください。

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
