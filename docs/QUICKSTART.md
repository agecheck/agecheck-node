# Quickstart

Use this page for shared runtime and configuration requirements across all Node framework adapters.

## Runtime

- Node.js `>=20`

## Required environment variables

```bash
AGECHECK_COOKIE_SECRET=replace_with_32_plus_bytes_random
AGECHECK_DEPLOYMENT_MODE=production
AGECHECK_REQUIRED_AGE=18
AGECHECK_GATE_HEADER_NAME=X-Age-Gate
AGECHECK_GATE_HEADER_REQUIRED_VALUE=true
```

Notes:
- `AGECHECK_COOKIE_SECRET` must be at least 32 bytes.
- `AGECHECK_DEPLOYMENT_MODE`:
  - `production`: accepts production issuer credentials and raises gate only when header policy requires it
  - `demo`: accepts demo + production issuer credentials and always raises gate

## Recommended pattern

Use framework adapter handlers for verify and gate enforcement:

- Express: `createExpressVerifyHandler`, `createExpressGateMiddleware`
- Fastify: `createFastifyVerifyHandler`, `createFastifyGateHook`
- Hono: `createHonoVerifyHandler`, `createHonoGateMiddleware`
- Nuxt: `createNuxtVerifyHandler`, `createNuxtGateMiddleware`

Most hostmasters should not manually call low-level cookie helpers.

## Troubleshooting

If verify response shows:

```json
{
  "verified": false,
  "code": "verify_failed",
  "error": "Failed to issue verification cookie"
}
```

check:
- Node runtime is `>=20`
- `AGECHECK_COOKIE_SECRET` is present in the running process and is at least 32 bytes
- request contains `payload.agegateway_session` as a UUID
- you are using adapter handlers instead of manual cookie issuance paths
