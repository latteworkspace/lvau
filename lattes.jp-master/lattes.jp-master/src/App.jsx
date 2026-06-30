import { Analytics } from "@vercel/analytics/react";
import { SpeedInsights } from "@vercel/speed-insights/react";
import { useEffect, useRef, useState } from "react";
import { SiteHeader } from "./components/SiteHeader.jsx";
import { HomePage } from "./pages/HomePage.jsx";
import { ToolboxPage } from "./pages/ToolboxPage.jsx";
import { LvauPage } from "./pages/LvauPage.jsx";

function getRoute() {
  const { pathname } = window.location;
  if (pathname === "/toolbox") return "/toolbox";
  if (pathname === "/lvau/ja" || pathname === "/ja/lvau") return "/lvau/ja";
  if (pathname === "/lvau") return "/lvau";
  return "/";
}

const debrisVectors = [
  ["-250px", "-160px", "18deg"],
  ["-180px", "-240px", "72deg"],
  ["-72px", "-280px", "126deg"],
  ["58px", "-268px", "184deg"],
  ["172px", "-220px", "236deg"],
  ["260px", "-120px", "288deg"],
  ["304px", "16px", "340deg"],
  ["228px", "146px", "28deg"],
  ["104px", "240px", "82deg"],
  ["-44px", "260px", "136deg"],
  ["-190px", "182px", "190deg"],
  ["-290px", "62px", "244deg"],
  ["-318px", "-54px", "298deg"],
  ["-118px", "-126px", "352deg"],
  ["112px", "-104px", "44deg"],
  ["148px", "118px", "98deg"],
];

export function App() {
  const [route, setRoute] = useState(getRoute);
  const [contactOpen, setContactOpen] = useState(false);
  const [exploding, setExploding] = useState(false);
  const explosionTimerRef = useRef(null);

  useEffect(() => {
    const handlePopState = () => setRoute(getRoute());
    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

useEffect(() => {
  const titleData =
    route === "/toolbox"
      ? {
          base: "latte toolbox",
          phrase: "small tools, made simple",
          frames: [
            "latte toolbox — small tools",
            "latte toolbox — made simple",
            "latte toolbox — useful things",
            "latte toolbox — browser tools",
          ],
        }
      : route === "/lvau" || route === "/lvau/ja"
        ? route === "/lvau/ja"
          ? {
              base: "lvau",
              phrase: "安全なローカルファイル暗号化",
              frames: [
                "lvau — 安全なローカルファイル暗号化",
                "lvau — boring cryptography",
                "lvau — xchacha20 + argon2id",
                "lvau — versioned envelope",
              ],
            }
          : {
              base: "lvau",
              phrase: "secure local file encryption",
              frames: [
                "lvau — secure local file encryption",
                "lvau — boring cryptography",
                "lvau — xchacha20 + argon2id",
                "lvau — versioned envelope",
              ],
            }
        : {
            base: "latte portfolio",
            phrase: "learning by making",
            frames: [
              "latte — learning by making",
              "latte — still learning",
              "latte — still building",
              "latte — small steps, real progress",
            ],
          };

  const explosionFrames = [
    "💣 3...",
    "💣 2...",
    "💣 1...",
    "💥 BOOM!",
    "🔥 芸術は爆発だ！",
    "✨ latte rebuilt.",
  ];

  let frame = 0;

  const interval = window.setInterval(() => {
    if (exploding) {
      document.title = explosionFrames[frame % explosionFrames.length];
      frame += 1;
      return;
    }

    document.title = titleData.frames[frame % titleData.frames.length];
    frame += 1;
  }, exploding ? 260 : 1800);

  return () => {
    window.clearInterval(interval);
    document.title = `${titleData.base} — ${titleData.phrase}`;
  };
}, [route, exploding]);

  useEffect(() => {
    return () => {
      if (explosionTimerRef.current) {
        clearTimeout(explosionTimerRef.current);
      }
    };
  }, []);

  function navigate(to) {
    const target = new URL(to, window.location.origin);
    const nextRoute =
      target.pathname === "/toolbox"
        ? "/toolbox"
        : target.pathname === "/lvau/ja" || target.pathname === "/ja/lvau"
          ? "/lvau/ja"
          : target.pathname === "/lvau"
            ? "/lvau"
            : "/";

    window.history.pushState({}, "", `${target.pathname}${target.hash}`);
    setRoute(nextRoute);

    requestAnimationFrame(() => {
      if (target.hash) {
        document.querySelector(target.hash)?.scrollIntoView({
          behavior: "smooth",
          block: "start",
        });
      } else {
        window.scrollTo({ top: 0, behavior: "smooth" });
      }
    });
  }

  function triggerExplosion() {
    if (explosionTimerRef.current) {
      clearTimeout(explosionTimerRef.current);
    }

    setExploding(false);

    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        setExploding(true);

        explosionTimerRef.current = setTimeout(() => {
          setExploding(false);
        }, 2600);
      });
    });
  }

  return (
    <div className={`site-frame${exploding ? " is-exploding" : ""}`}>
      <SiteHeader
        route={route}
        navigate={navigate}
        onContact={() => setContactOpen(true)}
      />

      {exploding ? (
        <div className="explosion-scene" aria-hidden="true">
          <div className="falling-bomb">
            <span className="bomb-body" />
            <span className="bomb-fuse" />
            <span className="bomb-spark" />
          </div>

          <div className="explosion-flash" />
          <div className="explosion-core" />
          <div className="explosion-ring" />
          <div className="explosion-smoke explosion-smoke--one" />
          <div className="explosion-smoke explosion-smoke--two" />
          <div className="explosion-smoke explosion-smoke--three" />

          <div className="explosion-debris">
            {debrisVectors.map(([x, y, r]) => (
              <span
                key={`${x}-${y}`}
                style={{
                  "--x": x,
                  "--y": y,
                  "--r": r,
                }}
              />
            ))}
          </div>
        </div>
      ) : null}

      {route === "/toolbox" ? (
        <ToolboxPage />
      ) : route === "/lvau" || route === "/lvau/ja" ? (
        <LvauPage locale={route === "/lvau/ja" ? "ja" : "en"} />
      ) : (
        <HomePage navigate={navigate} />
      )}

      <footer className="site-footer">
        <a
          className="wordmark wordmark--footer"
          href="/"
          onClick={(event) => {
            event.preventDefault();
            navigate("/");
          }}
        >
          latte
        </a>

        <button
          className="footer-quote"
          type="button"
          onClick={triggerExplosion}
          aria-label="芸術は爆発や！を実行する"
        >
          芸術は爆発や！
          <br />
          True art is an explosion!
        </button>

        <button
          className="text-link"
          onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
        >
          Back to top <span aria-hidden="true">↑</span>
        </button>
      </footer>

      {contactOpen ? (
        <div
          className="modal-backdrop"
          role="presentation"
          onMouseDown={() => setContactOpen(false)}
        >
          <section
            aria-labelledby="contact-title"
            aria-modal="true"
            className="contact-modal"
            role="dialog"
            onMouseDown={(event) => event.stopPropagation()}
          >
            <p className="section-index">Contact</p>
            <h2 id="contact-title">Still setting this up.</h2>
            <p>連絡先はまだないようです。</p>
            <button
              className="button button--light"
              onClick={() => setContactOpen(false)}
            >
              Close
            </button>
          </section>
        </div>
      ) : null}

      <Analytics />
      <SpeedInsights />
    </div>
  );
}
