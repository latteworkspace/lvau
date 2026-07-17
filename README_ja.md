# Lvau

> ローカルファイルと開発者ワークフロー向けの、検査可能な暗号化カプセル。

Lvau は CLI、ネイティブ GUI、暗号ライブラリ、バージョン付き `.lvau` プロトコル、実験的な自己展開 stub からなる Rust workspace です。現在のリリースは **0.4.0** です。

[English](README.md) | 日本語

[![CI](https://github.com/latteworkspace/lvau/actions/workflows/ci.yml/badge.svg)](https://github.com/latteworkspace/lvau/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> **セキュリティ警告:** Lvau は正式な第三者セキュリティ監査を完了しておらず、1.0 より前の形式は安定版ではありません。重要なデータに使う前に [SECURITY.md](SECURITY.md) と [脅威モデル](docs/THREAT_MODEL.md) を読んでください。

## クイックスタート

対話パスワードは非表示で入力し、stdout には出力しません。

```sh
lvau-cli encrypt --password --in-file secret.txt --out-file secret.txt.lvau
lvau-cli inspect --in-file secret.txt.lvau
lvau-cli decrypt --password --in-file secret.txt.lvau --out-file secret.restored.txt
```

ローカルの非対話自動化では、権限を制限したパスワードファイルを使います。末尾の CR/LF は取り除きますが、それ以外の文字は保持します。Unix では group/other が読めるパスワード・seed ファイルを拒否します。

```sh
printf '%s' '十分に強いパスフレーズへ置換' > password.txt
chmod 600 password.txt
lvau-cli encrypt --in-file secret.txt --out-file secret.txt.lvau --password-file password.txt
```

Windows では、Lvau を実行するアカウントだけが読める ACL を設定してください。Windows のパスワードファイル ACL は自動検証しません。パスワードや seed ファイルを commit しないでください。

## 0.4.0 の変更

- 新規ファイルは envelope 形式 v2 を使用します。AEAD の認証対象に平文長、nonce、受信者/KDF header、公開 label、content type、private metadata bytes、policy override marker を含めます。
- 空ペイロードにも認証済み AEAD frame を保存し、復号時に余分な暗号文を拒否します。
- 形式 v1 と旧 v0.2 envelope は、上限付き・完全消費 parser で読み続けられます。v1 の長さと header 外 metadata は payload 認証の対象ではなかったため、旧 capsule は復号して v2 として再暗号化してください。
- 高コスト処理の前に envelope size、recipient 数/種別、wrapped key size、nonce 構成、Argon2id profile tuple を検証します。
- 著者署名と approval seal は fingerprint/comment を署名し、v2 approval は暗号文にも結び付きます。ただし信頼済み鍵による明示的な検証は別途必要です。
- bundle manifest に canonical decode、checked offset、重複/path/collision 検査、entry ごとの BLAKE3 検証を追加しました。
- bundle 作成は特殊ファイルを拒否し、展開は `--force` を指定しても symlink/reparse point や複数 hardlink を持つ既存 target を上書きしません。
- recovery share は `SHA-256(secret)` を set identifier として公開せず、修正版 Shamir 実装 `blahaj` を使います。
- 機密出力は同一 directory の一時ファイル、fsync、Unix の制限権限、platform が対応する atomic replacement を使います。
- GUI の暗号処理を background worker へ移し、処理済み byte 数を表示します。dispatch 後は password/seed field を消去し、実験的 SFX は atomic temporary output へ streaming 生成します。
- CI は Linux/Windows/macOS を検証し、Actions を commit 固定し、release tag と全 crate version を照合し、checksum、CycloneDX SBOM、GitHub artifact attestation を準備します。

全体は [CHANGELOG.md](CHANGELOG.md) と [共通 Release Notes](docs/RELEASE_NOTES.md) を参照してください。

## 利用可能な機能と実験的機能

検証対象としている主な経路:

- XChaCha20-Poly1305、Argon2id、HKDF-SHA256 によるパスワード暗号化。
- 通常ファイルを全量 memory に載せない 1 MiB streaming chunk。
- 公開情報の inspect、認証付き decrypt/verify、inspect/verify/preflight の JSON、`--force` なしの上書き拒否。
- Ed25519 著者署名。
- 暗号化 manifest を持つパスワード式 directory bundle。
- ローカル policy lint、preflight report、recipient group、recovery share、structured-secret command。

実験的な経路:

- X25519 + ML-KEM-768 hybrid recipient encryption。
- `paranoid` / `extreme` cascade profile。
- `extreme` の LCO。これは難読化であり、暗号学的 security boundary ではありません。
- native GUI と Windows 自己展開 archive。
- workflow annotation としての approval seal、release metadata、recovery metadata。

Policy と approval はローカルの助言的 check です。存在するだけでは復号権限を強制せず、signer の信頼を証明せず、外部 M-of-N authorization system の代わりにはなりません。[docs/APPROVALS.md](docs/APPROVALS.md) と [docs/CAPSULE_POLICY.md](docs/CAPSULE_POLICY.md) を参照してください。

## インストール

Release archive は、権限を持つ人が tag workflow を実行した後にだけ [GitHub Releases](https://github.com/latteworkspace/lvau/releases) へ公開されます。

| Platform | 予定 asset 名 |
| --- | --- |
| Linux x86_64 | `lvau-x86_64-unknown-linux-gnu.tar.gz` |
| Windows x86_64 | `lvau-x86_64-pc-windows-msvc.zip` |
| macOS x86_64 | `lvau-x86_64-apple-darwin.tar.gz` |
| macOS aarch64 | `lvau-aarch64-apple-darwin.tar.gz` |

Archive を `checksums.txt` と照合し、利用可能なら GitHub CLI で artifact attestation も検証してください。各 archive には `lvau-cli`、`lvau-gui`、`lvau-stub`、両 README、`SECURITY.md`、`LICENSE` が入ります（Windows は `.exe`）。

### ソースから build

```sh
git clone https://github.com/latteworkspace/lvau.git
cd lvau
cargo build --locked --workspace --release
```

Binary は `target/release/` に生成されます。

### Explorer の右クリックメニュー

管理者権限なしで現在の user だけに `Lvau` menu を登録できます。`.lvau` file は復号し、それ以外は暗号化します。入力の隣に出力を作成し、既存 file は上書きせず、password は毎回 prompt します。

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\install-context-menu.ps1 `
  -BinaryPath .\target\release\lvau-cli.exe
```

削除:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\uninstall-context-menu.ps1
```

## CLI

正確な option は `lvau-cli <command> --help` を確認してください。Top-level command は次の通りです。

```text
keygen  encrypt  decrypt  inspect  verify  preflight  report  policy
bundle  sign-keygen  sign  verify-signature  approve  approvals
release  recipients  recovery  secret  self-test  doctor
```

よく使う例:

```sh
# Password encryption と検証
lvau-cli encrypt --password --in-file document.pdf --out-file document.pdf.lvau --profile balanced
lvau-cli verify --password --in-file document.pdf.lvau --json
lvau-cli decrypt --password --in-file document.pdf.lvau --out-file document.pdf

# 実験的 hybrid recipient encryption
lvau-cli keygen --out-base identity
lvau-cli encrypt --in-file input.txt --out-file output.lvau --pub-key identity.lvau-pub
lvau-cli decrypt --in-file output.lvau --out-file restored.txt --priv-key identity.lvau-key

# Password bundle
lvau-cli bundle pack --password --in-dir ./project-secrets --out-file secrets.lvau
lvau-cli bundle inspect --in-file secrets.lvau
lvau-cli bundle list --password --in-file secrets.lvau
lvau-cli bundle verify --password --in-file secrets.lvau
lvau-cli bundle extract --password --in-file secrets.lvau --out-dir ./restored --dry-run
lvau-cli bundle extract --password --in-file secrets.lvau --out-dir ./restored

# Signature
lvau-cli sign-keygen --out-base maintainer
lvau-cli sign --in-file secrets.lvau --out-file secrets-signed.lvau --signing-key maintainer.lvau-sign
lvau-cli verify-signature --in-file secrets-signed.lvau --verify-key maintainer.lvau-verify
```

Bundle の list/extract/verify は現在 password credential のみを受け付け、hybrid bundle extraction は CLI に公開していません。

### Security profile

| Profile | Argon2id parameter | Payload path | Status |
| --- | --- | --- | --- |
| `fast` | 16 MiB, 1 iteration, 1 lane | XChaCha20-Poly1305 | Test/短時間の local 処理向け |
| `balanced` | 64 MiB, 2 iterations, 1 lane | XChaCha20-Poly1305 | Default |
| `archive` | 256 MiB, 3 iterations, 2 lanes | XChaCha20-Poly1305 | 低頻度 archive 向け |
| `paranoid` | 1 GiB, 4 iterations, 4 lanes | AES-GCM + XChaCha cascade | 実験的 |
| `extreme` | 1 GiB, 4 iterations, 4 lanes | Cascade + LCO | 実験的 |

### Recovery share

Recovery は private key などの file を分割します。各 share を機密情報として保護してください。

```sh
lvau-cli recovery split --in-file identity.lvau-key --shares 5 --threshold 3 --out-dir ./shares
lvau-cli recovery inspect --in-file ./shares/share-1.lvau-share
lvau-cli recovery combine --shares-dir ./shares --out-file restored.lvau-key
```

### Structured secret

出力名は command が自動選択し、password は対話入力します。`secret print` は意図的に平文を stdout へ出すため、log に記録される環境では使わないでください。

```sh
lvau-cli secret encrypt --in-file .env
lvau-cli secret edit --in-file .env.lvau
lvau-cli secret print --in-file .env.lvau
lvau-cli secret decrypt --in-file .env.lvau
```

## GUI

`lvau-gui` は暗号処理を重複実装せず `lvau-core` を利用します。ローカル file の暗号化/復号と hybrid key generation 向けの実験的 UI で、全 CLI workflow との parity はまだありません。

```sh
cargo run --locked --release --package lvau-gui
```

## Security と format の限界

Lvau は password/private key と local machine が安全な場合に payload の機密性と完全性を保護します。Malware、keylogger、侵害済み OS、弱い password、盗まれた key、悪意ある出力 consumer、全 credential の紛失からは保護しません。

Envelope は algorithm、KDF parameter、recipient slot、nonce、概算 plaintext size、任意の public label を公開します。Bundle path と file metadata は既定で encrypted payload 内です。Signature、approval、release、recovery field は変更可能な annotation であり、別途検証・解釈が必要です。

Disk layout は 4-byte little-endian envelope length、上限付き postcard envelope、認証済み ciphertext chunk です。v2/v1 と migration は [docs/FORMAT.md](docs/FORMAT.md) を参照してください。

## Architecture

| Crate | 責務 |
| --- | --- |
| `lvau-protocol` | Serialized envelope / manifest type |
| `lvau-core` | Crypto、parser、file、bundle、signing、policy、recovery |
| `lvau-cli` | CLI UX と automation output |
| `lvau-gui` | `lvau-core` 上の実験的 native GUI |
| `lvau-stub` | 実験的 SFX extractor |

Public website は隣接する `lattes.jp` repository、OCI 上の server API は隣接する `lvau-api` repository にあります。Rust workspace 自体には OCI SDK や OCI control-plane client はありません。

## 開発

Documented local workflow は WSL2 / Ubuntu 26.04 を前提にします。

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
cargo build --locked --workspace --release
cargo tree --duplicates
```

[AGENTS.md](AGENTS.md)、[CONTRIBUTING.md](CONTRIBUTING.md)、[docs/ROADMAP.md](docs/ROADMAP.md) を読んでください。機密性の高い脆弱性を public issue へ投稿せず、[SECURITY.md](SECURITY.md) の手順を使ってください。

## License

MIT。詳細は [LICENSE](LICENSE) を参照してください。
