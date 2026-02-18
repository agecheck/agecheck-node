# Hostmaster End-to-End Integration

This guide is the production pattern for existing adult websites.

## Request flow

1. Browser requests protected route on your site.
2. Server middleware checks signed verification cookie.
3. If valid: server returns restricted content.
4. If missing/invalid and gate required: server redirects to gate page (`/ageverify`).
5. Gate flow returns JWT + `agegateway_session` to your backend `POST /verify`.
6. Backend verifies credential, sets signed cookie, redirects user back.

## Security boundary

- Gate decision and content access are enforced server-side.
- Cookie is stateless, signed, and time-bound.
- Cookie must be `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`.
- No personal data should be stored in the verification cookie.

## Required endpoints

- `GET /ageverify` (gate page route)
- `POST /verify` (JWT verification + set-cookie)
- Protected content routes (`/members/*`, `/videos/*`, etc.)

## Cookie payload model

Minimal payload model:

```json
{ "verified": true, "exp": 1700000000, "level": "18+" }
```

## Deployment modes

- `production`
  - accepts production credentials
  - gate enforced only when policy header indicates required
- `demo`
  - accepts demo + production credentials
  - gate always enforced

## Policy header model

You can drive gate policy with edge-injected headers, for example:

- `X-Age-Gate: true` to require gate
- no header / false to bypass gate

In demo mode, gate is still enforced regardless of header.

## Framework quick starts

- Express: `/docs/frameworks/express.md`
- Fastify: `/docs/frameworks/fastify.md`
- Hono: `/docs/frameworks/hono.md`
- Nuxt server: `/docs/frameworks/nuxt.md`
