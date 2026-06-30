import { getApiKeyRecord, consumeApiQuota } from "../../server/apiKeys.js";
import {
  allowCors,
  json,
  logEvent,
  readJsonBody,
} from "../../server/http.js";
import { transform } from "../../server/transforms.js";

function bearerToken(req) {
  const authorization = req.headers.authorization || "";
  return authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
}

export default async function handler(req, res) {
  const startedAt = Date.now();
  allowCors(res);

  if (req.method === "OPTIONS") {
    res.statusCode = 204;
    return res.end();
  }
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST, OPTIONS");
    return json(res, 405, { error: "Method not allowed." });
  }

  try {
    const apiKey = bearerToken(req);
    const record = await getApiKeyRecord(apiKey);
    if (!record || !["active", "trialing"].includes(record.status)) {
      return json(res, 401, { error: "Invalid or inactive API key." });
    }

    const quota = await consumeApiQuota(apiKey);
    res.setHeader("X-RateLimit-Limit", String(quota.minuteLimit));
    res.setHeader(
      "X-RateLimit-Remaining",
      String(Math.max(0, quota.minuteLimit - quota.perMinute)),
    );
    res.setHeader("X-Monthly-Limit", String(quota.monthlyLimit));
    res.setHeader(
      "X-Monthly-Remaining",
      String(Math.max(0, quota.monthlyLimit - quota.monthly)),
    );

    if (!quota.allowed) {
      return json(res, 429, { error: "Usage limit exceeded." });
    }

    const { operation, input } = readJsonBody(req);
    const output = transform(operation, input);

    logEvent("info", "api_transform_completed", {
      route: "/api/v1/transform",
      operation,
      durationMs: Date.now() - startedAt,
    });
    return json(res, 200, {
      operation,
      output,
      usage: {
        monthly: quota.monthly,
        limit: quota.monthlyLimit,
      },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Request failed.";
    logEvent("error", "api_transform_failed", {
      route: "/api/v1/transform",
      error: message,
      durationMs: Date.now() - startedAt,
    });
    const status = /Unsupported|input|Invalid date|JSON/.test(message) ? 400 : 500;
    return json(res, status, { error: message });
  }
}
