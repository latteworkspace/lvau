import {
  ArrowRight,
  ArrowUpRight,
  BookOpenText,
  Code,
  Compass,
  Sparkle,
} from "@phosphor-icons/react";

const experiments = [
  {
    number: "01",
    title: "Portfolio Study",
    status: "Personal study",
    description:
      "余白、文字組み、情報の順序を考えながら組み立てた、このサイト自体のデザイン習作です。",
    image: "/assets/portfolio-study.png",
    href: "#about",
  },
  {
    number: "02",
    title: "Toolbox",
    status: "In progress",
    description:
      "JSON整形や文字数カウントなど、ブラウザ内で完結するツールをまとめています。",
    image: "/assets/toolbox-study.png",
    href: "/toolbox",
  },
  {
    number: "03",
    title: "Lvau",
    status: "Rust / Security",
    description:
      "XChaCha20-Poly1305、Argon2id、HKDFを使ったファイル暗号化ツールです。",
    image: "/assets/motion-notes.png",
    href: "/lvau",
  },
];

const topics = [
  "Web Design",
  "Frontend",
  "Creative Coding",
  "UI Details",
  "Accessibility",
];

export function HomePage({ navigate }) {
  function handleInternalLink(event, href) {
    if (!href.startsWith("/")) return;
    event.preventDefault();
    navigate(href);
  }

  return (
    <main>
      <section className="hero" id="top">
        <div className="hero-copy">
          <p className="section-index">01 / orbit</p>
          <h1>Learning by making useful things.</h1>
          <p className="hero-intro">
            UI、UXやプログラミングを学んでいる学生です。
            いろいろなことに手を出したり、ツールやアプリをつくっています。
          </p>
          <div className="hero-actions">
            <a className="button button--light" href="#experiments">
              View experiments
              <ArrowRight aria-hidden="true" size={18} weight="bold" />
            </a>
            <a className="text-link" href="#about">
              About latte <ArrowRight aria-hidden="true" size={17} />
            </a>
          </div>
        </div>

        <div className="hero-art" aria-hidden="true">
          <img
            alt=""
            decoding="async"
            fetchPriority="high"
            src="/assets/orbit-star.png"
          />
          <span className="coordinate coordinate--top">x + 35.68</span>
          <span className="coordinate coordinate--bottom">latte / origin</span>
        </div>
      </section>

      <section className="exploring-strip" aria-label="Currently exploring">
        <p className="section-index">02 / exploring</p>
        <h2>Currently exploring</h2>
        <div className="topic-list">
          {topics.map((topic) => (
            <span key={topic}>{topic}</span>
          ))}
        </div>
      </section>

      <section className="experiments-section" id="experiments">
        <div className="section-heading">
          <div>
            <p className="section-index">03 / experiments</p>
            <h2>Small experiments</h2>
          </div>
          <p>
            いつかzennとか乗っけたい場所
          </p>
        </div>

        <div className="experiment-grid">
          {experiments.map((experiment) => (
            <a
              className="experiment-card"
              href={experiment.href}
              key={experiment.title}
              onClick={(event) => handleInternalLink(event, experiment.href)}
            >
              <div className="experiment-image">
                <img
                  alt={`${experiment.title}の抽象ビジュアル`}
                  loading="lazy"
                  src={experiment.image}
                />
              </div>
              <div className="experiment-meta">
                <span>{experiment.number}</span>
                <span>{experiment.status}</span>
              </div>
              <div className="experiment-title-row">
                <h3>{experiment.title}</h3>
                <ArrowUpRight aria-hidden="true" size={22} />
              </div>
              <p>{experiment.description}</p>
            </a>
          ))}
        </div>
      </section>

      <section className="quote-section" id="words">
        <div className="quote-orbit" aria-hidden="true">
          <Sparkle size={38} weight="fill" />
        </div>
        <p className="section-index">04 / words</p>
        <blockquote>
          <p>“Stay hungry. Stay foolish.”</p>
          <footer>
            Words shared by Steve Jobs at Stanford Commencement, 2005.
            Originally from <cite>The Whole Earth Catalog</cite>.
          </footer>
        </blockquote>
        <a
          className="text-link"
          href="https://news.stanford.edu/stories/2005/06/youve-got-find-love-jobs-says"
          rel="noreferrer"
          target="_blank"
        >
          Read the speech <ArrowUpRight aria-hidden="true" size={16} />
        </a>
      </section>

      <section className="about-section" id="about">
        <div className="about-heading">
          <p className="section-index">05 / about</p>
          <h2>Small steps. Real progress.</h2>
        </div>

        <div className="about-body">
          <p>
            プログラミングなどを独学で学んでいます。
            フロントエンドでなく、バックエンドやサーバーにも興味があります。
          </p>
          <p>
            VSCodeとChromeを行き来しています
            作ることを頑張っています。
          </p>

          <div className="about-principles">
            <div>
              <Compass aria-hidden="true" size={22} />
              <span>Curious</span>
              <p>気になったことは、まず自分で試してみること</p>
            </div>

            <div>
              <Code aria-hidden="true" size={22} />
              <span>Hands-on</span>
              <p>思いついたら、まずは少し作って動かしてみること</p>
            </div>

            <div>
              <BookOpenText aria-hidden="true" size={22} />
              <span>Learning</span>
              <p>うまくいったことも、失敗したことも、次に活かせるように残すこと</p>
            </div>
          </div>
        </div>
      </section>
    </main>
  );
}
