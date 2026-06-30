import { Redis } from "@upstash/redis";

let redis;

export function isRedisConfigured() {
  return Boolean(
    (process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL) &&
      (process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN),
  );
}

export function getRedis() {
  if (!isRedisConfigured()) {
    throw new Error("Redis is not configured.");
  }

  if (!redis) {
    redis = new Redis({
      url:
        process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL,
      token:
        process.env.UPSTASH_REDIS_REST_TOKEN ||
        process.env.KV_REST_API_TOKEN,
    });
  }

  return redis;
}
