import { updateSubscriptionStatus } from "../../server/apiKeys.js";
import { json, logEvent, readRawBody } from "../../server/http.js";
import { getStripe } from "../../server/stripe.js";

export default async function handler(req, res) {
  const startedAt = Date.now();
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return json(res, 405, { error: "Method not allowed." });
  }

  try {
    if (!process.env.STRIPE_WEBHOOK_SECRET) {
      return json(res, 503, { error: "Webhook is not configured." });
    }

    const signatureHeader = req.headers["stripe-signature"];
    const signature = Array.isArray(signatureHeader)
      ? signatureHeader[0]
      : signatureHeader;
    if (!signature) {
      return json(res, 400, { error: "Missing Stripe signature." });
    }
    const event = getStripe().webhooks.constructEvent(
      await readRawBody(req),
      signature,
      process.env.STRIPE_WEBHOOK_SECRET,
    );

    if (
      event.type === "customer.subscription.updated" ||
      event.type === "customer.subscription.deleted"
    ) {
      const subscription = event.data.object;
      await updateSubscriptionStatus(subscription.id, subscription.status);
    }

    logEvent("info", "stripe_webhook_processed", {
      route: "/api/billing/webhook",
      eventType: event.type,
      durationMs: Date.now() - startedAt,
    });
    return json(res, 200, { received: true });
  } catch (error) {
    logEvent("error", "stripe_webhook_failed", {
      route: "/api/billing/webhook",
      error: error instanceof Error ? error.message : String(error),
      durationMs: Date.now() - startedAt,
    });
    return json(res, 400, { error: "Invalid webhook signature." });
  }
}
