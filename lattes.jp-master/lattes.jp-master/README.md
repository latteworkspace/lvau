# latte

Student portfolio and browser toolbox built with React, Vite, and Vercel Functions.

## Local development

```bash
npm install
npm run dev
```

The browser tools run locally in the browser. Tool inputs are not sent to the
usage endpoint or Vercel Analytics.

## Verification

```bash
npm test
npm run build
```

## Vercel analytics

The React integrations are mounted in `src/App.jsx`:

- `@vercel/speed-insights/react`
- `@vercel/analytics/react`

Tool executions emit a `tool_used` custom event containing only the tool ID and
action name. Enable Web Analytics and Speed Insights for the Vercel project.

## Aggregate usage counts

Install Upstash Redis from the Vercel Marketplace and set:

```text
UPSTASH_REDIS_REST_URL
UPSTASH_REDIS_REST_TOKEN
```

Without Redis, the UI shows honest per-device counts from `localStorage`.
With Redis, `/api/usage` stores aggregate counts without receiving tool input.

## API Pro subscription

API Pro uses Stripe Checkout Sessions in subscription mode. Create a recurring
Stripe Price, configure the Customer Portal, and set the variables from
`.env.example`.

Required production values:

```text
APP_URL
STRIPE_SECRET_KEY
STRIPE_API_PRO_PRICE_ID
STRIPE_WEBHOOK_SECRET
API_KEY_SECRET
UPSTASH_REDIS_REST_URL
UPSTASH_REDIS_REST_TOKEN
VITE_API_PRO_ENABLED=true
```

Register the webhook endpoint:

```text
POST /api/billing/webhook
```

Subscribe it to:

- `customer.subscription.updated`
- `customer.subscription.deleted`

The success flow derives an API key, stores only its SHA-256 hash mapping in
Redis, and removes the Checkout Session ID from the browser URL after delivery.
Subscription status changes revoke or restore access through the webhook.

The paid endpoint is:

```text
POST /api/v1/transform
Authorization: Bearer latte_live_...
```

Default limits are 10,000 requests per month and 60 requests per minute. Change
them with `API_PRO_MONTHLY_LIMIT` and `API_PRO_RATE_LIMIT_PER_MINUTE`.

## Ads

The toolbox contains one restrained ad slot. It displays a neutral sponsor
space until both values are configured:

```text
VITE_ADSENSE_CLIENT
VITE_ADSENSE_SLOT
```

AdSense still requires domain review, policy compliance, and publisher setup.
No advertiser or revenue is fabricated when those values are absent.
