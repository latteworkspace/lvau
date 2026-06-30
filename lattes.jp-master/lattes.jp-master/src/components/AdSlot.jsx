import { useEffect } from "react";

const client = import.meta.env.VITE_ADSENSE_CLIENT;
const slot = import.meta.env.VITE_ADSENSE_SLOT;

export function AdSlot() {
  useEffect(() => {
    if (!client || !slot) return;

    const scriptId = "latte-adsense";
    if (!document.getElementById(scriptId)) {
      const script = document.createElement("script");
      script.async = true;
      script.crossOrigin = "anonymous";
      script.id = scriptId;
      script.src = `https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=${client}`;
      document.head.appendChild(script);
    }

    try {
      (window.adsbygoogle = window.adsbygoogle || []).push({});
    } catch {
      // Ad blockers and unapproved domains can prevent initialization.
    }
  }, []);

  if (client && slot) {
    return (
      <aside className="ad-slot" aria-label="Advertisement">
        <span>Advertisement</span>
        <ins
          className="adsbygoogle"
          data-ad-client={client}
          data-ad-format="auto"
          data-ad-slot={slot}
          data-full-width-responsive="true"
          style={{ display: "block" }}
        />
      </aside>
    );
  }

  return (
    <aside className="ad-slot ad-slot--house" aria-label="Sponsor space">
      <span>Advertisement</span>
      <div>
        <p>Quiet space for one sponsor.</p>
        <small>広告収益は、無料のブラウザツールの維持に使います。</small>
      </div>
      <span className="ad-slot__status">Sponsor space</span>
    </aside>
  );
}
