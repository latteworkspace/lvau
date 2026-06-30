import { LvauWeb } from "../components/LvauWeb.jsx";

const pageContent = {
  en: {
    langLabel: "Language",
    langSelf: "English",
    langOther: "日本語",
    langOtherHref: "/lvau/ja",
    eyebrow: "project / lvau",
    heroTitle: "Secure local file encryption, boring by design.",
    heroBody:
      "Lvau is a Rust-based file encryption toolkit built around modern, well-established cryptographic primitives. It focuses on safe defaults, inspectable metadata, and practical CLI / GUI workflows.",
    githubCta: "View on GitHub",
    securityCta: "Read security model",
    console: `$ lvau-cli encrypt --in secret.txt --out encrypted.lvau --profile balanced\n\n[profile] balanced\n[kdf]     argon2id\n[aead]    xchacha20-poly1305\n[format]  versioned envelope\n\noutput: encrypted.lvau`,
    strip: [
      ["Rust", "workspace architecture"],
      ["CLI + GUI", "scriptable and accessible"],
      [".lvau", "versioned envelope"],
      ["MIT", "open source license"],
    ],
    securityIndex: "01 / security model",
    securityTitle: "Standard primitives. Clear boundaries.",
    securityBody:
      "Lvau avoids proprietary cryptography and custom ciphers as security boundaries. The goal is not to look mysterious; the goal is to make the important parts easy to review.",
    primitives: [
      {
        title: "XChaCha20-Poly1305",
        label: "AEAD",
        description:
          "Authenticated encryption with a 192-bit nonce. Designed to keep the file encryption boundary simple and reviewable.",
      },
      {
        title: "Argon2id",
        label: "KDF",
        description:
          "Password-based key derivation with per-file random salts and selectable cost profiles.",
      },
      {
        title: "HKDF",
        label: "Key separation",
        description:
          "Expands derived key material into purpose-specific keys instead of reusing one secret everywhere.",
      },
      {
        title: "Versioned envelope",
        label: ".lvau",
        description:
          "Stores cryptographic metadata in a strongly structured format and binds it as AEAD AAD.",
      },
    ],
    principlesIndex: "02 / principles",
    principlesTitle: "Built to be hard to misuse.",
    principles: [
      "No custom cipher as a security boundary",
      "Local file encryption first",
      "CLI and GUI workflows",
      "Safe metadata inspection",
      "Sensitive key material zeroization where practical",
      "Future-ready protocol layout",
    ],
    quickStartIndex: "03 / quick start",
    quickStartTitle: "Clone, build, encrypt.",
    quickStartBody:
      "The repository currently exposes the Rust workspace and project source. Build locally with Cargo, then use the CLI commands below.",
    roadmapIndex: "04 / roadmap",
    roadmapTitle: "Protocol layout for future upgrades.",
    roadmapBody:
      "The current design leaves room for recipient-based encryption, signing, self-extracting archives, operational key providers, and post-quantum hybrid modes.",
    roadmap: [
      {
        title: "Recipient encryption",
        description: "X25519 key wrapping for asymmetric file sharing workflows.",
      },
      {
        title: "Signed manifests",
        description: "Ed25519 signing support for tamper-evident metadata and manifests.",
      },
      {
        title: "SFX support",
        description: "Self-extracting archive flow using a minimal decryptor stub.",
      },
      {
        title: "Operational key providers",
        description: "KMS/HSM abstraction interfaces while preserving local encryption semantics.",
      },
      {
        title: "PQC hybrids",
        description: "Future ML-KEM / ML-DSA hybrid support when the protocol is ready.",
      },
    ],
    noteIndex: "05 / note",
    noteTitle: "Security claims stay conservative.",
    noteBody:
      "Lvau is designed around established primitives and safe defaults, but users should still evaluate the implementation, threat model, and release maturity before relying on it for sensitive production use.",
    repoCta: "Open repository",
  },
  ja: {
    langLabel: "言語",
    langSelf: "日本語",
    langOther: "English",
    langOtherHref: "/lvau",
    eyebrow: "project / lvau",
    heroTitle: "安全なローカルファイル暗号化を、標準的で堅実に。",
    heroBody:
      "Lvau は Rust で作られたローカルファイル暗号化ツールキットです。XChaCha20-Poly1305、Argon2id、HKDF、バージョン付き Envelope など、実績のある暗号プリミティブを使い、安全なデフォルトと扱いやすい CLI / GUI を重視しています。",
    githubCta: "GitHub で見る",
    securityCta: "セキュリティモデルを読む",
    console: `$ lvau-cli encrypt --in secret.txt --out encrypted.lvau --profile balanced\n\n[profile] balanced\n[kdf]     argon2id\n[aead]    xchacha20-poly1305\n[format]  versioned envelope\n\noutput: encrypted.lvau`,
    strip: [
      ["Rust", "workspace 構成"],
      ["CLI + GUI", "自動化と手動操作の両対応"],
      [".lvau", "バージョン付き Envelope"],
      ["MIT", "オープンソースライセンス"],
    ],
    securityIndex: "01 / security model",
    securityTitle: "標準的なプリミティブ。明確な境界。",
    securityBody:
      "Lvau は独自暗号やプロプライエタリな難読化をセキュリティ境界として扱いません。強そうに見せることではなく、重要な部分をレビューしやすく保つことを優先しています。",
    primitives: [
      {
        title: "XChaCha20-Poly1305",
        label: "AEAD",
        description:
          "192-bit nonce を持つ認証付き暗号です。ファイル暗号化の中核をシンプルで確認しやすい構造に保ちます。",
      },
      {
        title: "Argon2id",
        label: "KDF",
        description:
          "パスワードから鍵を導出するための KDF です。ファイルごとのランダム salt とプロファイル別のコスト設定を使います。",
      },
      {
        title: "HKDF",
        label: "Key separation",
        description:
          "導出された鍵素材を用途別の鍵に分離し、同じ秘密値を複数用途に使い回さない設計にします。",
      },
      {
        title: "Versioned envelope",
        label: ".lvau",
        description:
          "暗号メタデータを構造化して保存し、AEAD の AAD としてバインドします。",
      },
    ],
    principlesIndex: "02 / principles",
    principlesTitle: "誤用しにくい設計を優先。",
    principles: [
      "独自暗号をセキュリティ境界にしない",
      "ローカルファイル暗号化を第一にする",
      "CLI と GUI の両方に対応する",
      "安全なメタデータ確認を用意する",
      "実用上可能な範囲で秘密鍵素材を zeroize する",
      "将来拡張しやすいプロトコル構成にする",
    ],
    quickStartIndex: "03 / quick start",
    quickStartTitle: "clone して、build して、暗号化。",
    quickStartBody:
      "現在のリポジトリでは Rust workspace とソースコードを公開しています。Cargo でビルドし、以下の CLI コマンドで暗号化・復号・メタデータ確認ができます。",
    roadmapIndex: "04 / roadmap",
    roadmapTitle: "将来の拡張を見据えたプロトコル構成。",
    roadmapBody:
      "受信者ベースの暗号化、署名、自己展開アーカイブ、KMS/HSM 連携、ポスト量子暗号ハイブリッドなどを将来的に追加できる構造を想定しています。",
    roadmap: [
      {
        title: "Recipient encryption",
        description: "X25519 による鍵ラッピングで、受信者指定のファイル共有を可能にする構想です。",
      },
      {
        title: "Signed manifests",
        description: "Ed25519 署名で、manifest やメタデータの改ざん検知を行う構想です。",
      },
      {
        title: "SFX support",
        description: "最小限の復号 stub を使った自己展開アーカイブの流れを追加する構想です。",
      },
      {
        title: "Operational key providers",
        description: "ローカル暗号化の意味を保ちながら、KMS/HSM 抽象インターフェースを追加する構想です。",
      },
      {
        title: "PQC hybrids",
        description: "プロトコル側の準備が整った段階で、ML-KEM / ML-DSA ハイブリッド対応を検討します。",
      },
    ],
    noteIndex: "05 / note",
    noteTitle: "セキュリティ表現は控えめに。",
    noteBody:
      "Lvau は実績のあるプリミティブと安全なデフォルトを重視して設計されています。ただし、重要な用途で使う前には、実装、脅威モデル、リリースの成熟度を確認してください。",
    repoCta: "リポジトリを開く",
  },
};

const quickStart = `git clone https://github.com/lasder-ca/lvau.git
cd lvau
cargo build --release

lvau-cli encrypt --in secret.txt --out encrypted.lvau --profile balanced
lvau-cli decrypt --in encrypted.lvau --out secret.txt
lvau-cli inspect --in encrypted.lvau`;

export function LvauPage({ locale = "en" }) {
  const content = pageContent[locale] ?? pageContent.en;

  return (
    <main className="lvau-page" lang={locale === "ja" ? "ja" : "en"}>
      <section className="lvau-hero">
        <div className="lvau-hero__copy">
          <div className="lvau-kicker-row">
            <p className="section-index">{content.eyebrow}</p>
            <div className="lvau-language-switch" aria-label={content.langLabel}>
              <span>{content.langSelf}</span>
              <a href={content.langOtherHref}>{content.langOther}</a>
            </div>
          </div>
          <h1>{content.heroTitle}</h1>
          <p>{content.heroBody}</p>
          <div className="hero-actions">
            <a
              className="button button--light"
              href="https://github.com/lasder-ca/lvau"
              rel="noreferrer"
              target="_blank"
            >
              {content.githubCta}
              <span aria-hidden="true">↗</span>
            </a>
            <a className="text-link" href="#security-model">
              {content.securityCta} <span aria-hidden="true">↓</span>
            </a>
          </div>
        </div>

        <div className="lvau-console" aria-label="Lvau command example">
          <div className="lvau-console__bar">
            <span />
            <span />
            <span />
            <strong>lvau-cli</strong>
          </div>
          <pre>{content.console}</pre>
        </div>
      </section>

      <section style={{ display: 'flex', justifyContent: 'center', width: '100%', padding: '40px 0', backgroundColor: '#0f111a' }}>
        <div style={{ width: '100%', maxWidth: '800px' }}>
          <LvauWeb lang={locale === "ja" ? "ja" : "en"} />
        </div>
      </section>

      <section className="lvau-strip" aria-label="Lvau highlights">
        {content.strip.map(([title, description]) => (
          <div key={title}>
            <strong>{title}</strong>
            <span>{description}</span>
          </div>
        ))}
      </section>

      <section className="lvau-section" id="security-model">
        <div className="section-heading">
          <div>
            <p className="section-index">{content.securityIndex}</p>
            <h2>{content.securityTitle}</h2>
          </div>
          <p>{content.securityBody}</p>
        </div>

        <div className="lvau-primitive-grid">
          {content.primitives.map((item) => (
            <article className="lvau-primitive-card" key={item.title}>
              <span>{item.label}</span>
              <h3>{item.title}</h3>
              <p>{item.description}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="lvau-principles">
        <div>
          <p className="section-index">{content.principlesIndex}</p>
          <h2>{content.principlesTitle}</h2>
        </div>
        <ul>
          {content.principles.map((principle) => (
            <li key={principle}>
              <span aria-hidden="true">✓</span>
              {principle}
            </li>
          ))}
        </ul>
      </section>

      <section className="lvau-section lvau-quickstart" id="quick-start">
        <div className="section-heading">
          <div>
            <p className="section-index">{content.quickStartIndex}</p>
            <h2>{content.quickStartTitle}</h2>
          </div>
          <p>{content.quickStartBody}</p>
        </div>

        <div className="lvau-code-block">
          <pre>{quickStart}</pre>
        </div>
      </section>

      <section className="lvau-section">
        <div className="section-heading">
          <div>
            <p className="section-index">{content.roadmapIndex}</p>
            <h2>{content.roadmapTitle}</h2>
          </div>
          <p>{content.roadmapBody}</p>
        </div>

        <div className="lvau-roadmap">
          {content.roadmap.map((item, index) => (
            <article key={item.title}>
              <span>0{index + 1}</span>
              <div>
                <h3>{item.title}</h3>
                <p>{item.description}</p>
              </div>
            </article>
          ))}
        </div>
      </section>

      <section className="lvau-disclaimer">
        <p className="section-index">{content.noteIndex}</p>
        <h2>{content.noteTitle}</h2>
        <p>{content.noteBody}</p>
        <a
          className="button button--light"
          href="https://github.com/lasder-ca/lvau"
          rel="noreferrer"
          target="_blank"
        >
          {content.repoCta}
          <span aria-hidden="true">↗</span>
        </a>
      </section>
    </main>
  );
}
