import Stripe from "stripe";

let stripe;

export function isStripeConfigured() {
  return Boolean(
    process.env.STRIPE_SECRET_KEY &&
      process.env.STRIPE_API_PRO_PRICE_ID &&
      process.env.STRIPE_WEBHOOK_SECRET,
  );
}

export function getStripe() {
  if (!process.env.STRIPE_SECRET_KEY) {
    throw new Error("Stripe is not configured.");
  }
  if (!stripe) {
    stripe = new Stripe(process.env.STRIPE_SECRET_KEY, {
      apiVersion: "2026-02-25.clover",
      maxNetworkRetries: 2,
    });
  }
  return stripe;
}
