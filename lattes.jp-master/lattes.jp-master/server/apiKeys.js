import {
  createHash,
  createHmac,
  timingSafeEqual,
} from "node:crypto";
import { getRedis } from "./redis.js";

const KEY_PREFIX = "latte_live_";

function requireSecret() {
  const secret = process.env.API_KEY_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error("API_KEY_SECRET must be at least 32 characters.");
  }
  return secret;
}

export function deriveApiKey(checkoutSessionId) {
  const digest = createHmac("sha256", requireSecret())
    .update(checkoutSessionId)
    .digest("base64url")
    .slice(0, 40);
  return `${KEY_PREFIX}${digest}`;
}

export function hashApiKey(apiKey) {
  return createHash("sha256").update(apiKey).digest("hex");
}

export function isPlausibleApiKey(apiKey) {
  if (typeof apiKey !== "string" || !apiKey.startsWith(KEY_PREFIX)) return false;
  const expected = Buffer.from(KEY_PREFIX);
  const actual = Buffer.from(apiKey.slice(0, KEY_PREFIX.length));
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

export async function saveApiKeyRecord(apiKey, record) {
  const redis = getRedis();
  const keyHash = hashApiKey(apiKey);
  const normalized = {
    ...record,
    keyPrefix: apiKey.slice(0, 18),
    updatedAt: new Date().toISOString(),
  };
  await redis.set(`latte:api:key:${keyHash}`, JSON.stringify(normalized));
  await redis.set(`latte:subscription:${record.subscriptionId}`, keyHash);
  return normalized;
}

export async function getApiKeyRecord(apiKey) {
  if (!isPlausibleApiKey(apiKey)) return null;
  const value = await getRedis().get(`latte:api:key:${hashApiKey(apiKey)}`);
  if (!value) return null;
  return typeof value === "string" ? JSON.parse(value) : value;
}

export async function updateSubscriptionStatus(subscriptionId, status) {
  const redis = getRedis();
  const keyHash = await redis.get(`latte:subscription:${subscriptionId}`);
  if (!keyHash) return false;
  const storageKey = `latte:api:key:${keyHash}`;
  const current = await redis.get(storageKey);
  if (!current) return false;
  const record = typeof current === "string" ? JSON.parse(current) : current;
  await redis.set(
    storageKey,
    JSON.stringify({
      ...record,
      status,
      updatedAt: new Date().toISOString(),
    }),
  );
  return true;
}

export async function consumeApiQuota(apiKey) {
  const redis = getRedis();
  const keyHash = hashApiKey(apiKey);
  const now = new Date();
  const month = now.toISOString().slice(0, 7);
  const minute = now.toISOString().slice(0, 16);
  const monthlyLimit = Number(process.env.API_PRO_MONTHLY_LIMIT || 10_000);
  const minuteLimit = Number(process.env.API_PRO_RATE_LIMIT_PER_MINUTE || 60);

  const monthlyKey = `latte:api:usage:${keyHash}:${month}`;
  const minuteKey = `latte:api:rate:${keyHash}:${minute}`;
  const [monthly, perMinute] = await Promise.all([
    redis.incr(monthlyKey),
    redis.incr(minuteKey),
  ]);

  if (monthly === 1) await redis.expire(monthlyKey, 60 * 60 * 24 * 45);
  if (perMinute === 1) await redis.expire(minuteKey, 120);

  return {
    allowed: monthly <= monthlyLimit && perMinute <= minuteLimit,
    monthly,
    monthlyLimit,
    perMinute,
    minuteLimit,
  };
}
