import assert from "node:assert/strict";
import test from "node:test";
import {
  deriveApiKey,
  isPlausibleApiKey,
} from "../server/apiKeys.js";
import { transform } from "../server/transforms.js";

test("server transforms cover the paid API operations", () => {
  assert.equal(transform("json.minify", '{"a": 1}'), '{"a":1}');
  assert.equal(transform("url.encode", "a b"), "a%20b");
  assert.equal(
    transform("base64.decode", transform("base64.encode", "ラテ")),
    "ラテ",
  );
  assert.equal(transform("sha256", "latte").length, 64);
  assert.equal(transform("unix.toTimestamp", "1970-01-01T00:00:01Z"), "1");
});

test("API keys are deterministic and use the latte prefix", () => {
  process.env.API_KEY_SECRET = "test-secret-that-is-at-least-32-characters";
  const first = deriveApiKey("cs_test_same_session");
  const second = deriveApiKey("cs_test_same_session");

  assert.equal(first, second);
  assert.equal(isPlausibleApiKey(first), true);
  assert.equal(isPlausibleApiKey("other_key"), false);
});
