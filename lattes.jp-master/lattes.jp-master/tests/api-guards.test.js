import assert from "node:assert/strict";
import test from "node:test";
import transformHandler from "../api/v1/transform.js";

function createResponse() {
  return {
    body: "",
    headers: {},
    statusCode: 0,
    end(body = "") {
      this.body = body;
    },
    setHeader(key, value) {
      this.headers[key] = value;
    },
  };
}

test("paid transform API rejects missing credentials before reading Redis", async () => {
  const response = createResponse();
  await transformHandler(
    {
      body: { operation: "json.format", input: "{}" },
      headers: {},
      method: "POST",
    },
    response,
  );

  assert.equal(response.statusCode, 401);
  assert.match(response.body, /Invalid or inactive API key/);
});
