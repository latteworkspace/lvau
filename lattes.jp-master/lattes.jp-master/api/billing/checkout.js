import { json, logEvent } from "../../server/http.js";
import { getStripe } from "../../server/stripe.js";

export default async function handler(req, res) {
  const startedAt = Date.now();
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return json(res, 405, { error: "Method not allowed." });
  }

  try {
    if (!process.env.STRIPE_API_PRO_PRICE_ID) {
      return json(res, 503, { error: "API Pro is not configured yet." });
    }

    const vercelHost =
      process.env.VERCEL_URL || process.env.VERCEL_PROJECT_PRODUCTION_URL;
    const appUrl = (
      process.env.APP_URL || (vercelHost ? `https://${vercelHost}` : "")
    ).replace(/\/$/, "");
    if (!appUrl) {
      return json(res, 503, { error: "APP_URL is not configured." });
    }

    const session = await getStripe().checkout.sessions.create({
      mode: "subscription",
      line_items: [{ price: process.env.STRIPE_API_PRO_PRICE_ID, quantity: 1 }],
      allow_promotion_codes: true,
      billing_address_collection: "auto",
      success_url: `${appUrl}/toolbox?checkout=success&session_id={CHECKOUT_SESSION_ID}#api-pro`,
      cancel_url: `${appUrl}/toolbox?checkout=cancelled#api-pro`,
      metadata: { product: "latte-api-pro" },
      subscription_data: {
        metadata: { product: "latte-api-pro" },
      },
    });

    logEvent("info", "checkout_created", {
      route: "/api/billing/checkout",
      durationMs: Date.now() - startedAt,
    });
    return json(res, 200, { url: session.url });
  } catch (error) {
    logEvent("error", "checkout_failed", {
      route: "/api/billing/checkout",
      error: error instanceof Error ? error.message : String(error),
      durationMs: Date.now() - startedAt,
    });
    return json(res, 500, { error: "Checkout could not be created." });
  }
}
