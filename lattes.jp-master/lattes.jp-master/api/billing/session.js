import { deriveApiKey, saveApiKeyRecord } from "../../server/apiKeys.js";
import { json, logEvent } from "../../server/http.js";
import { getStripe } from "../../server/stripe.js";

export default async function handler(req, res) {
  const startedAt = Date.now();
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return json(res, 405, { error: "Method not allowed." });
  }

  try {
    const sessionId = String(req.query?.session_id || "");
    if (!sessionId.startsWith("cs_")) {
      return json(res, 400, { error: "Invalid Checkout Session." });
    }

    const stripe = getStripe();
    const session = await stripe.checkout.sessions.retrieve(sessionId, {
      expand: ["subscription"],
    });
    const subscription = session.subscription;

    if (
      session.status !== "complete" ||
      !subscription ||
      typeof subscription === "string" ||
      !["active", "trialing"].includes(subscription.status)
    ) {
      return json(res, 402, { error: "Subscription is not active." });
    }

    const apiKey = deriveApiKey(session.id);
    await saveApiKeyRecord(apiKey, {
      customerId:
        typeof session.customer === "string"
          ? session.customer
          : session.customer?.id,
      subscriptionId: subscription.id,
      status: subscription.status,
      plan: "api-pro",
      checkoutSessionId: session.id,
      createdAt: new Date().toISOString(),
    });

    logEvent("info", "api_key_delivered", {
      route: "/api/billing/session",
      subscriptionId: subscription.id,
      durationMs: Date.now() - startedAt,
    });
    return json(res, 200, {
      apiKey,
      plan: "api-pro",
      monthlyLimit: Number(process.env.API_PRO_MONTHLY_LIMIT || 10_000),
    });
  } catch (error) {
    logEvent("error", "api_key_delivery_failed", {
      route: "/api/billing/session",
      error: error instanceof Error ? error.message : String(error),
      durationMs: Date.now() - startedAt,
    });
    return json(res, 500, { error: "API key could not be delivered." });
  }
}
