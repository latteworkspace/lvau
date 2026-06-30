import { getRedis, isRedisConfigured } from "../server/redis.js";
import { json, logEvent, readJsonBody } from "../server/http.js";

const allowedTools = new Set([
  "json",
  "url",
  "base64",
  "unix",
  "color",
  "counter",
  "uuid",
  "hash",
]);
const allowedActions = new Set([
  "primary",
  "secondary",
  "minify",
]);

export default async function handler(req, res) {
  const startedAt = Date.now();

  if (!isRedisConfigured()) {
    return json(res, 503, {
      enabled: false,
      error: "Usage aggregation is not configured.",
    });
  }

  try {
    const redis = getRedis();
    if (req.method === "GET") {
      const keys = [...allowedTools].map((tool) => `latte:usage:tool:${tool}`);
      const [total, ...counts] = await redis.mget("latte:usage:total", ...keys);
      return json(res, 200, {
        enabled: true,
        total: Number(total) || 0,
        byTool: Object.fromEntries(
          [...allowedTools].map((tool, index) => [
            tool,
            Number(counts[index]) || 0,
          ]),
        ),
      });
    }

    if (req.method !== "POST") {
      res.setHeader("Allow", "GET, POST");
      return json(res, 405, { error: "Method not allowed." });
    }

    const { tool, action } = readJsonBody(req);
    if (!allowedTools.has(tool) || !allowedActions.has(action)) {
      return json(res, 400, { error: "Invalid usage event." });
    }

    const [total, toolTotal] = await Promise.all([
      redis.incr("latte:usage:total"),
      redis.incr(`latte:usage:tool:${tool}`),
    ]);

    logEvent("info", "tool_usage_recorded", {
      route: "/api/usage",
      tool,
      action,
      durationMs: Date.now() - startedAt,
    });
    return json(res, 200, { ok: true, total, toolTotal });
  } catch (error) {
    logEvent("error", "tool_usage_failed", {
      route: "/api/usage",
      error: error instanceof Error ? error.message : String(error),
      durationMs: Date.now() - startedAt,
    });
    return json(res, 500, { error: "Could not record usage." });
  }
}
