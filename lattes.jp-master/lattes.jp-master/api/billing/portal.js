import { getApiKeyRecord } from "../../server/apiKeys.js";
import { json, readJsonBody } from "../../server/http.js";
import { getStripe } from "../../server/stripe.js";

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return json(res, 405, { error: "Method not allowed." });
  }

  try {
    const { apiKey } = readJsonBody(req);
    const record = await getApiKeyRecord(apiKey);
    if (!record?.customerId) {
      return json(res, 401, { error: "Invalid API key." });
    }

    const vercelHost =
      process.env.VERCEL_URL || process.env.VERCEL_PROJECT_PRODUCTION_URL;
    const appUrl = (
      process.env.APP_URL || (vercelHost ? `https://${vercelHost}` : "")
    ).replace(/\/$/, "");
    if (!appUrl) {
      return json(res, 503, { error: "APP_URL is not configured." });
    }
    const session = await getStripe().billingPortal.sessions.create({
      customer: record.customerId,
      return_url: `${appUrl}/toolbox#api-pro`,
    });
    return json(res, 200, { url: session.url });
  } catch {
    return json(res, 500, { error: "Customer Portal is unavailable." });
  }
}
