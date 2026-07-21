# Lvau

> ローカルファイルを暗号化し、形式や公開情報をあとから確認できる暗号化カプセル。

Lvauは、ローカルファイルの暗号化を扱う実験的なRustワークスペースです。コマンドラインツール、ネイティブGUI、再利用可能な暗号ライブラリ、バージョン管理された`.lvau`形式、実験的な自己展開機能を含みます。現在のリリースは**0.5.0**です。

[English](README.md) | 日本語

[![CI](https://github.com/lasder-ca/lvau/actions/workflows/ci.yml/badge.svg)](https://github.com/lasder-ca/lvau/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> [!WARNING]
> Lvauは正式な第三者セキュリティ監査を完了しておらず、1.0より前に形式が変わる可能性があります。重要なデータへ使う前に、[SECURITY.md](SECURITY.md)と[脅威モデル](docs/THREAT_MODEL.md)を確認してください。

## Lvauでできること

- XChaCha20-Poly1305、Argon2id、HKDF-SHA256を使ったパスワード暗号化。
- 通常ファイルの内容をすべてメモリへ載せないストリーミング暗号化。
- 内容を復号せずに、形式や公開情報を確認する検査機能。
- 認証付きの復号・検証と、機械処理に使えるJSON出力。
- Ed25519による著者署名。
- 暗号化された目録を持つ、パスワード保護されたディレクトリバンドル。
- 補助的なローカルポリシー確認と事前検査レポート、受信者グループ、復旧共有、構造化シークレット向けコマンド。
- `lvau-core`の暗号処理を再利用するネイティブGUI。

ポリシー確認は実験的な補助機能です。`decrypt`や`bundle extract`では自動実行されないため、復号や展開の前に条件を満たす必要がある場合は、`policy lint`または`preflight`を別の手順として実行してください。

ハイブリッド受信者暗号化、複数方式を重ねるプロファイル、承認メタデータ、復旧機能、GUI、自己展開アーカイブは実験段階です。

## クイックスタート

パスワードは画面に表示せず、標準出力にも書き込みません。

```sh
lvau-cli encrypt --password --in-file secret.txt --out-file secret.txt.lvau
lvau-cli inspect --in-file secret.txt.lvau
lvau-cli verify --password --in-file secret.txt.lvau
lvau-cli decrypt --password --in-file secret.txt.lvau --out-file secret.restored.txt
```

ローカルの自動処理でパスワードファイルを使う場合は、読み取り権限を制限します。

```sh
printf '%s' '十分に強いパスフレーズへ置換' > password.txt
chmod 600 password.txt
lvau-cli encrypt --in-file secret.txt --out-file secret.txt.lvau --password-file password.txt
```

Windowsでは、Lvauを実行するアカウントだけが読めるようにパスワードファイルのACLを設定してください。広すぎる権限をCLI側で拒否する確認はUnix環境だけで動作するため、WindowsのACLは自分で制限する必要があります。

パスワード、秘密鍵、シード、復旧共有、認証情報をGitへ追加しないでください。

## 0.5.0の変更

- ディレクトリバンドルは、平文全体をメモリに保持せず、固定64 KiBのバッファーでファイル内容を処理します。
- バンドル作成時にサイズとBLAKE3を2回検証し、展開時はすべての項目を認証してから出力を原子的に作成します。
- 形式v2のHKDFラベル、nonce導出、チャンクAADを、互換性ベクトル付きのバージョン管理された方式一覧へ集約しました。
- `secrecy` 0.10と`x25519-dalek` 3へ移行しました。
- 検査、検証、事前確認、レポート、ポリシー確認のJSON出力はスキーマversion 1を使います。
- 0.5.0もenvelope形式v2を書き込みます。実験的な形式v3は0.6.0で別に導入する予定です。

詳しくは[CHANGELOG.md](CHANGELOG.md)、[docs/JSON_OUTPUT.md](docs/JSON_OUTPUT.md)、[docs/ROADMAP.md](docs/ROADMAP.md)を確認してください。

## インストール

リリース用ワークフローが正常に完了した版だけを、[GitHub Releases](https://github.com/lasder-ca/lvau/releases)で公開します。

ソースからビルドする場合:

```sh
git clone https://github.com/lasder-ca/lvau.git
cd lvau
cargo build --locked --workspace --release
```

実行ファイルは`target/release/`へ生成されます。

## コマンドライン

正確なオプションは`lvau-cli <command> --help`で確認できます。

```text
keygen  encrypt  decrypt  inspect  verify  preflight  report  policy
bundle  sign-keygen  sign  verify-signature  approve  approvals
release  recipients  recovery  secret  self-test  doctor
```

よく使う例:

```sh
# パスワード暗号化と検証
lvau-cli encrypt --password --in-file document.pdf --out-file document.pdf.lvau --profile balanced
lvau-cli verify --password --in-file document.pdf.lvau --json
lvau-cli decrypt --password --in-file document.pdf.lvau --out-file document.pdf

# パスワードで保護したディレクトリバンドル
lvau-cli bundle pack --password --in-dir ./project-secrets --out-file secrets.lvau
lvau-cli bundle verify --password --in-file secrets.lvau
lvau-cli bundle extract --password --in-file secrets.lvau --out-dir ./restored --dry-run
lvau-cli bundle extract --password --in-file secrets.lvau --out-dir ./restored

# 著者署名
lvau-cli sign-keygen --out-base maintainer
lvau-cli sign --in-file secrets.lvau --out-file secrets-signed.lvau --signing-key maintainer.lvau-sign
lvau-cli verify-signature --in-file secrets-signed.lvau --verify-key maintainer.lvau-verify
```

## セキュリティプロファイル

| プロファイル | Argon2idの設定 | 暗号化方式 | 状態 |
|---|---|---|---|
| `fast` | 16 MiB、1反復、1レーン | XChaCha20-Poly1305 | テストや短いローカル処理向け |
| `balanced` | 64 MiB、2反復、1レーン | XChaCha20-Poly1305 | 既定値 |
| `archive` | 256 MiB、3反復、2レーン | XChaCha20-Poly1305 | 低頻度の保管向け |
| `paranoid` | 1 GiB、4反復、4レーン | AES-GCMとXChaChaの多段処理 | 実験的 |
| `extreme` | 1 GiB、4反復、4レーン | 多段処理とLCO | 実験的。LCOは難読化であり、セキュリティ境界ではありません |

## GUI

`lvau-gui`は、ローカルファイルの暗号化、復号、ハイブリッド鍵生成に使う実験的なデスクトップ画面です。暗号処理は`lvau-core`へ集約しており、コマンドラインの全機能にはまだ対応していません。

```sh
cargo run --locked --release --package lvau-gui
```

## セキュリティと形式の制限

Lvauが保護できるのは、パスワードや秘密鍵、利用する端末が安全に保たれている場合のデータの機密性と完全性です。マルウェア、キーロガー、侵害されたOS、弱いパスワード、盗まれた鍵、悪意のある出力先、すべての認証情報の紛失からは保護できません。

envelopeには、方式名、KDF設定、受信者スロット、nonce、平文のおおよその大きさ、任意の公開ラベルが記録されます。バンドル内のパスとファイル情報は既定で暗号化されます。署名、承認、リリース、復旧に関する項目は別の注釈であり、明示的な検証と解釈が必要です。

形式v2/v1の構造と移行方法は[docs/FORMAT.md](docs/FORMAT.md)にあります。

## 構成

| クレート | 役割 |
|---|---|
| `lvau-protocol` | envelopeと目録のシリアライズ型 |
| `lvau-core` | 暗号処理、解析、ファイル、バンドル、署名、ポリシー、復旧 |
| `lvau-cli` | コマンドライン画面と自動処理向け出力 |
| `lvau-gui` | `lvau-core`を使う実験的なネイティブGUI |
| `lvau-stub` | 実験的な自己展開アーカイブ |

公開サイトは`lasder-ca/lattes.jp`で管理しています。OCI上のサービスは別リポジトリで管理しており、このRustワークスペースにクラウド認証情報やOCI制御APIのクライアントは含みません。

## 開発

ローカル開発手順は、WSL2上のUbuntu 26.04を前提としています。

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
cargo build --locked --workspace --release
cargo tree --duplicates
cargo run --locked --quiet --package lvau-cli -- self-test
```

[AGENTS.md](AGENTS.md)、[CONTRIBUTING.md](CONTRIBUTING.md)、[docs/ROADMAP.md](docs/ROADMAP.md)も確認してください。機密性の高い脆弱性は公開Issueへ書かず、[SECURITY.md](SECURITY.md)の手順で報告してください。

## ライセンス

[MIT License](LICENSE)で公開しています。
