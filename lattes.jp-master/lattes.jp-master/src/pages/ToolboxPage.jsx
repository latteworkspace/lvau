import {
  ArrowRight,
  BracketsCurly,
  CheckCircle,
  Clock,
  Code,
  Copy,
  Database,
  Hash,
  Link,
  MagnifyingGlass,
  PaintBrush,
  TextAa,
  Trash,
} from "@phosphor-icons/react";
import { useEffect, useMemo, useRef, useState } from "react";
import { AdSlot } from "../components/AdSlot.jsx";
import { ApiProSection } from "../components/ApiProSection.jsx";
import { getLocalUsage, recordToolUsage } from "../lib/usage.js";

const tools = [
  {
    id: "json",
    name: "JSON Formatter",
    category: "Development",
    description: "JSONを読みやすく整形、または圧縮します。",
    Icon: BracketsCurly,
  },
  {
    id: "url",
    name: "URL Encoder",
    category: "Development",
    description: "URL文字列をencode / decodeします。",
    Icon: Link,
  },
  {
    id: "base64",
    name: "Base64",
    category: "Data",
    description: "UTF-8文字列をBase64へ変換します。",
    Icon: Code,
  },
  {
    id: "unix",
    name: "Unix Time",
    category: "Data",
    description: "日時とUnix timeを相互に確認します。",
    Icon: Clock,
  },
  {
    id: "color",
    name: "Color Converter",
    category: "Design",
    description: "HEXをRGB / HSLへ変換します。",
    Icon: PaintBrush,
  },
  {
    id: "counter",
    name: "Character Counter",
    category: "Text",
    description: "文字数、行数、byte数を数えます。",
    Icon: TextAa,
  },
  {
    id: "uuid",
    name: "UUID Generator",
    category: "Development",
    description: "UUID v4をブラウザ内で生成します。",
    Icon: Database,
  },
  {
    id: "hash",
    name: "Hash Generator",
    category: "Data",
    description: "文字列からSHA-256 hashを生成します。",
    Icon: Hash,
  },
];

const categories = ["All", "Text", "Development", "Data", "Design"];

const initialValues = {
  json: '{\n  "name": "latte",\n  "type": "student project",\n  "localOnly": true\n}',
  url: "https://example.com/search?q=small tools",
  base64: "Learning by making.",
  unix: "",
  color: "#d8d8d8",
  counter: "ここに文字を入力すると、文字数や行数を確認できます。",
  uuid: "",
  hash: "latte",
};

function bytesToBase64(value) {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

function base64ToText(value) {
  const binary = atob(value);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

function hexToRgb(hex) {
  const normalized = hex.trim().replace("#", "");
  if (!/^[0-9a-fA-F]{6}$/.test(normalized)) {
    throw new Error("6桁のHEXを入力してください。");
  }
  const number = Number.parseInt(normalized, 16);
  return {
    r: (number >> 16) & 255,
    g: (number >> 8) & 255,
    b: number & 255,
  };
}

function rgbToHsl({ r, g, b }) {
  const red = r / 255;
  const green = g / 255;
  const blue = b / 255;
  const max = Math.max(red, green, blue);
  const min = Math.min(red, green, blue);
  let hue = 0;
  let saturation = 0;
  const lightness = (max + min) / 2;

  if (max !== min) {
    const delta = max - min;
    saturation =
      lightness > 0.5 ? delta / (2 - max - min) : delta / (max + min);
    if (max === red) hue = (green - blue) / delta + (green < blue ? 6 : 0);
    if (max === green) hue = (blue - red) / delta + 2;
    if (max === blue) hue = (red - green) / delta + 4;
    hue /= 6;
  }

  return {
    h: Math.round(hue * 360),
    s: Math.round(saturation * 100),
    l: Math.round(lightness * 100),
  };
}

async function sha256(value) {
  const data = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export function ToolboxPage() {
  const [activeCategory, setActiveCategory] = useState("All");
  const [activeTool, setActiveTool] = useState("json");
  const [query, setQuery] = useState("");
  const [values, setValues] = useState(initialValues);
  const [result, setResult] = useState(
    JSON.stringify(JSON.parse(initialValues.json), null, 2),
  );
  const [message, setMessage] = useState("");
  const [localUsage, setLocalUsage] = useState(getLocalUsage);
  const [aggregateUsage, setAggregateUsage] = useState(null);
  const searchRef = useRef(null);

  const currentTool = tools.find((tool) => tool.id === activeTool) ?? tools[0];
  const ActiveToolIcon = currentTool.Icon;
  const source = values[activeTool] ?? "";

  const visibleTools = useMemo(() => {
    const searchTerm = query.trim().toLowerCase();
    return tools.filter((tool) => {
      const categoryMatches =
        activeCategory === "All" || tool.category === activeCategory;
      const searchMatches =
        !searchTerm ||
        `${tool.name} ${tool.description} ${tool.category}`
          .toLowerCase()
          .includes(searchTerm);
      return categoryMatches && searchMatches;
    });
  }, [activeCategory, query]);

  useEffect(() => {
    function handleShortcut(event) {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        searchRef.current?.focus();
      }
    }
    window.addEventListener("keydown", handleShortcut);
    return () => window.removeEventListener("keydown", handleShortcut);
  }, []);

  useEffect(() => {
    let active = true;
    fetch("/api/usage")
      .then(async (response) => {
        if (!response.ok) return null;
        return response.json();
      })
      .then((payload) => {
        if (active && payload?.enabled) setAggregateUsage(payload);
      })
      .catch(() => {});
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    setMessage("");
    if (activeTool === "json") {
      try {
        setResult(JSON.stringify(JSON.parse(values.json), null, 2));
      } catch {
        setResult("");
      }
      return;
    }
    if (activeTool === "unix") {
      const now = new Date();
      setValues((current) => ({
        ...current,
        unix: current.unix || now.toISOString().slice(0, 19),
      }));
      setResult(
        `Seconds: ${Math.floor(now.getTime() / 1000)}\nMilliseconds: ${now.getTime()}`,
      );
      return;
    }
    if (activeTool === "uuid") {
      const uuid = crypto.randomUUID();
      setValues((current) => ({ ...current, uuid }));
      setResult(uuid);
      return;
    }
    setResult("");
  }, [activeTool]);

  function updateSource(value) {
    setValues((current) => ({ ...current, [activeTool]: value }));
    setMessage("");
  }

  async function runTool(mode = "primary") {
    try {
      let nextResult = "";
      if (activeTool === "json") {
        const parsed = JSON.parse(source);
        nextResult =
          mode === "minify"
            ? JSON.stringify(parsed)
            : JSON.stringify(parsed, null, 2);
      }
      if (activeTool === "url") {
        nextResult =
          mode === "secondary"
            ? decodeURIComponent(source)
            : encodeURIComponent(source);
      }
      if (activeTool === "base64") {
        nextResult =
          mode === "secondary" ? base64ToText(source) : bytesToBase64(source);
      }
      if (activeTool === "unix") {
        const date = new Date(source);
        if (Number.isNaN(date.getTime())) {
          throw new Error("有効な日時を入力してください。");
        }
        nextResult = `ISO: ${date.toISOString()}\nSeconds: ${Math.floor(
          date.getTime() / 1000,
        )}\nMilliseconds: ${date.getTime()}`;
      }
      if (activeTool === "color") {
        const rgb = hexToRgb(source);
        const hsl = rgbToHsl(rgb);
        nextResult = `HEX: ${source.toUpperCase()}\nRGB: rgb(${rgb.r}, ${rgb.g}, ${rgb.b})\nHSL: hsl(${hsl.h}, ${hsl.s}%, ${hsl.l}%)`;
      }
      if (activeTool === "counter") {
        const bytes = new TextEncoder().encode(source).length;
        const characters = Array.from(source).length;
        const lines = source ? source.split(/\r\n|\r|\n/).length : 0;
        const words = source.trim() ? source.trim().split(/\s+/).length : 0;
        nextResult = `Characters: ${characters}\nWords: ${words}\nLines: ${lines}\nBytes (UTF-8): ${bytes}`;
      }
      if (activeTool === "uuid") {
        nextResult = crypto.randomUUID();
        setValues((current) => ({ ...current, uuid: nextResult }));
      }
      if (activeTool === "hash") {
        nextResult = await sha256(source);
      }
      setResult(nextResult);
      setMessage("Done");
      setLocalUsage(recordToolUsage(activeTool, mode));
    } catch (error) {
      setResult("");
      setMessage(error instanceof Error ? error.message : "変換できませんでした。");
    }
  }

  async function copyResult() {
    if (!result) return;
    await navigator.clipboard.writeText(result);
    setMessage("Copied");
  }

  function selectTool(toolId) {
    setActiveTool(toolId);
    requestAnimationFrame(() => {
      document.querySelector("#workbench")?.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    });
  }

  return (
    <main className="toolbox-page">
      <section className="toolbox-hero">
        <div>
          <p className="section-index">01 / utility</p>
          <h1>Toolbox.</h1>
          <p>ブラウザだけで使える、小さくて実用的な道具。</p>
        </div>
        <div className="toolbox-star" aria-hidden="true">
          <img alt="" src="/assets/orbit-star.png" />
        </div>
        <label className="tool-search">
          <MagnifyingGlass aria-hidden="true" size={23} />
          <span className="sr-only">Search tools</span>
          <input
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search tools"
            ref={searchRef}
            type="search"
            value={query}
          />
          <kbd>⌘ K</kbd>
        </label>
        <div className="toolbox-facts" aria-label="Toolbox facts">
          <div>
            <strong>{tools.length}</strong>
            <span>Browser tools</span>
          </div>
          <div>
            <strong>{aggregateUsage?.total ?? localUsage.total}</strong>
            <span>
              {aggregateUsage ? "Recorded tool runs" : "Runs on this device"}
            </span>
          </div>
          <div>
            <strong>Local</strong>
            <span>Inputs stay in your browser</span>
          </div>
          <div>
            <strong>No sign-up</strong>
            <span>For browser tools</span>
          </div>
        </div>
      </section>

      <section className="tool-directory">
        <aside className="category-nav" aria-label="Tool categories">
          <div className="category-nav__title">
            <span>Directory</span>
            <small>Pick a tool</small>
          </div>
          {categories.map((category) => (
            <button
              className={activeCategory === category ? "is-active" : ""}
              key={category}
              onClick={() => setActiveCategory(category)}
            >
              {category}
            </button>
          ))}
        </aside>

        <div className="tool-grid">
          {visibleTools.length ? (
            visibleTools.map(({ Icon, ...tool }) => (
              <button
                className={activeTool === tool.id ? "tool-card is-active" : "tool-card"}
                key={tool.id}
                onClick={() => selectTool(tool.id)}
              >
                <span className="tool-icon">
                  <Icon aria-hidden="true" size={27} />
                </span>
                <span>
                  <strong>{tool.name}</strong>
                  <small>{tool.description}</small>
                  <em>
                    {aggregateUsage?.byTool?.[tool.id] ??
                      localUsage.byTool[tool.id] ??
                      0}{" "}
                    uses
                  </em>
                </span>
                <ArrowRight aria-hidden="true" size={20} />
              </button>
            ))
          ) : (
            <div className="empty-tools">
              <p>No tools found.</p>
              <button
                className="text-link"
                onClick={() => {
                  setQuery("");
                  setActiveCategory("All");
                }}
              >
                Clear search
              </button>
            </div>
          )}
        </div>
      </section>

      <AdSlot />

      <section className="workbench" id="workbench">
        <header className="workbench-header">
          <div>
            <span className="tool-icon">
              <ActiveToolIcon aria-hidden="true" size={27} />
            </span>
            <div>
              <h2>{currentTool.name}</h2>
              <p>{currentTool.description}</p>
            </div>
          </div>
          <span className="privacy-note">
            <CheckCircle aria-hidden="true" size={17} weight="fill" />
            Local processing only
          </span>
        </header>

        <div className="workbench-grid">
          <label className="editor-field">
            <span>Input</span>
            {activeTool === "color" ? (
              <div className="color-input-row">
                <input
                  aria-label="Color picker"
                  onChange={(event) => updateSource(event.target.value)}
                  type="color"
                  value={/^#[0-9a-fA-F]{6}$/.test(source) ? source : "#d8d8d8"}
                />
                <input
                  aria-label="HEX color"
                  onChange={(event) => updateSource(event.target.value)}
                  spellCheck="false"
                  value={source}
                />
              </div>
            ) : (
              <textarea
                onChange={(event) => updateSource(event.target.value)}
                spellCheck="false"
                value={source}
              />
            )}
          </label>

          <label className="editor-field">
            <span>Output</span>
            <textarea readOnly spellCheck="false" value={result} />
          </label>
        </div>

        <div className="workbench-actions">
          <div>
            <button className="button button--light" onClick={() => runTool("primary")}>
              {activeTool === "uuid" ? "Generate" : "Run"}
            </button>
            {["json", "url", "base64"].includes(activeTool) ? (
              <button
                className="button button--dark"
                onClick={() =>
                  runTool(activeTool === "json" ? "minify" : "secondary")
                }
              >
                {activeTool === "json"
                  ? "Minify"
                  : activeTool === "url"
                    ? "Decode"
                    : "Decode"}
              </button>
            ) : null}
            <button
              className="icon-button"
              onClick={() => {
                updateSource("");
                setResult("");
              }}
              title="Clear"
            >
              <Trash aria-hidden="true" size={19} />
              <span>Clear</span>
            </button>
          </div>
          <div className="result-actions">
            {message ? <span role="status">{message}</span> : null}
            <button className="icon-button" disabled={!result} onClick={copyResult}>
              <Copy aria-hidden="true" size={19} />
              <span>Copy output</span>
            </button>
          </div>
        </div>
      </section>

      <ApiProSection />
    </main>
  );
}
