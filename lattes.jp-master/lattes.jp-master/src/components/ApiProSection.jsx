import {
  ArrowRight,
  Check,
  Copy,
  Key,
  LockKey,
  X,
} from "@phosphor-icons/react";
import { useEffect, useState } from "react";

const example = `curl -X POST https://your-domain.dev/api/v1/transform \\
  -H "Authorization: Bearer latte_live_..." \\
  -H "Content-Type: application/json" \\
  -d '{"operation":"json.format","input":"{\\"hello\\":true}"}'`;

export function ApiProSection() {
  const [checkoutState, setCheckoutState] = useState("idle");
  const [delivery, setDelivery] = useState(null);
  const [copied, setCopied] = useState(false);
  const [managementKey, setManagementKey] = useState("");
  const [managementOpen, setManagementOpen] = useState(false);
  const enabled = import.meta.env.VITE_API_PRO_ENABLED === "true";

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const sessionId = params.get("session_id");
    if (params.get("checkout") !== "success" || !sessionId) return;

    let active = true;
    setCheckoutState("loading");
    fetch(`/api/billing/session?session_id=${encodeURIComponent(sessionId)}`)
      .then(async (response) => {
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error ?? "API key delivery failed.");
        return payload;
      })
      .then((payload) => {
        if (!active) return;
        setDelivery(payload);
        setCheckoutState("success");
        window.history.replaceState({}, "", "/toolbox#api-pro");
      })
      .catch((error) => {
        if (!active) return;
        setCheckoutState("error");
        setDelivery({ error: error.message });
      });

    return () => {
      active = false;
    };
  }, []);

  async function startCheckout() {
    setCheckoutState("loading");
    try {
      const response = await fetch("/api/billing/checkout", { method: "POST" });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error ?? "Checkout is unavailable.");
      window.location.assign(payload.url);
    } catch (error) {
      setCheckoutState("error");
      setDelivery({ error: error.message });
    }
  }

  async function copyKey() {
    if (!delivery?.apiKey) return;
    await navigator.clipboard.writeText(delivery.apiKey);
    setCopied(true);
  }

  async function openPortal() {
    setCheckoutState("loading");
    try {
      const response = await fetch("/api/billing/portal", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ apiKey: managementKey }),
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.error ?? "Customer Portal is unavailable.");
      }
      window.location.assign(payload.url);
    } catch (error) {
      setCheckoutState("error");
      setDelivery({ error: error.message });
    }
  }

  return (
    <>
      <section className="api-pro-section" id="api-pro">
        <div className="api-pro-copy">
          <p className="section-index">03 / api access</p>
          <h2>Use the tools from your own app.</h2>
          <p>
            ブラウザ版は無料のまま。API ProはStripeの月額サブスクリプションと
            API key、quota、利用回数計測を組み合わせた拡張用の入口です。
          </p>

          <ul>
            <li>
              <Check aria-hidden="true" size={17} />
              10,000 requests / month by default
            </li>
            <li>
              <Check aria-hidden="true" size={17} />
              Stripe-hosted Checkout and Customer Portal
            </li>
            <li>
              <Check aria-hidden="true" size={17} />
              API key hashing, rate limits, and usage counters
            </li>
          </ul>

          <div className="api-pro-actions">
            <button
              className="button button--light"
              disabled={!enabled || checkoutState === "loading"}
              onClick={startCheckout}
            >
              {enabled ? "Subscribe to API Pro" : "API Pro setup required"}
              <ArrowRight aria-hidden="true" size={18} />
            </button>
            <span>
              Price is configured in Stripe.
              <br />
              No price is shown until a real Price ID is connected.
            </span>
          </div>
          <button
            className="manage-subscription-link"
            onClick={() => setManagementOpen((current) => !current)}
          >
            Manage an existing subscription
          </button>
          {managementOpen ? (
            <div className="portal-form">
              <label>
                <span>API key</span>
                <input
                  autoComplete="off"
                  onChange={(event) => setManagementKey(event.target.value)}
                  placeholder="latte_live_..."
                  type="password"
                  value={managementKey}
                />
              </label>
              <button
                className="button button--dark"
                disabled={!managementKey || checkoutState === "loading"}
                onClick={openPortal}
              >
                Open Customer Portal
              </button>
            </div>
          ) : null}
        </div>

        <div className="api-example">
          <div className="api-example__header">
            <span>
              <LockKey aria-hidden="true" size={17} />
              Authenticated request
            </span>
            <span>POST /api/v1/transform</span>
          </div>
          <pre>
            <code>{example}</code>
          </pre>
          <div className="api-operations">
            <span>json.format</span>
            <span>url.encode</span>
            <span>base64.encode</span>
            <span>sha256</span>
          </div>
        </div>
      </section>

      {checkoutState === "success" || checkoutState === "error" ? (
        <div className="modal-backdrop" role="presentation">
          <section
            aria-labelledby="api-key-title"
            aria-modal="true"
            className="contact-modal api-key-modal"
            role="dialog"
          >
            <button
              aria-label="Close"
              className="modal-close"
              onClick={() => {
                setCheckoutState("idle");
                setDelivery(null);
              }}
            >
              <X size={20} />
            </button>
            {delivery?.apiKey ? (
              <>
                <Key aria-hidden="true" size={28} />
                <h2 id="api-key-title">Your API key</h2>
                <p>
                  このキーは秘密情報です。公開リポジトリやブラウザコードへ直接
                  埋め込まないでください。
                </p>
                <code className="delivered-key">{delivery.apiKey}</code>
                <button className="button button--light" onClick={copyKey}>
                  <Copy aria-hidden="true" size={18} />
                  {copied ? "Copied" : "Copy API key"}
                </button>
              </>
            ) : (
              <>
                <h2 id="api-key-title">Setup incomplete</h2>
                <p>{delivery?.error ?? "API key could not be delivered."}</p>
              </>
            )}
          </section>
        </div>
      ) : null}
    </>
  );
}
