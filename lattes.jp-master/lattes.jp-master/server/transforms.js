import { createHash } from "node:crypto";

const MAX_INPUT_LENGTH = 100_000;

export const supportedOperations = new Set([
  "json.format",
  "json.minify",
  "url.encode",
  "url.decode",
  "base64.encode",
  "base64.decode",
  "unix.toTimestamp",
  "sha256",
]);

export function transform(operation, input) {
  if (!supportedOperations.has(operation)) {
    throw new Error("Unsupported operation.");
  }
  if (typeof input !== "string") {
    throw new Error("input must be a string.");
  }
  if (input.length > MAX_INPUT_LENGTH) {
    throw new Error(`input exceeds ${MAX_INPUT_LENGTH} characters.`);
  }

  switch (operation) {
    case "json.format":
      return JSON.stringify(JSON.parse(input), null, 2);
    case "json.minify":
      return JSON.stringify(JSON.parse(input));
    case "url.encode":
      return encodeURIComponent(input);
    case "url.decode":
      return decodeURIComponent(input);
    case "base64.encode":
      return Buffer.from(input, "utf8").toString("base64");
    case "base64.decode":
      return Buffer.from(input, "base64").toString("utf8");
    case "unix.toTimestamp": {
      const date = new Date(input);
      if (Number.isNaN(date.getTime())) throw new Error("Invalid date.");
      return String(Math.floor(date.getTime() / 1000));
    }
    case "sha256":
      return createHash("sha256").update(input).digest("hex");
    default:
      throw new Error("Unsupported operation.");
  }
}
