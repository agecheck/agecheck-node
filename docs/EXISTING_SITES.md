# Existing Site Integration

This guide describes how to add AgeCheck to an existing adult website without redesigning page templates.

## Recommended pattern

1. Keep your existing page rendering code.
2. Add middleware/server guard on protected routes.
3. Redirect unverified users to your gate route (for example `/ageverify`).
4. Verify JWT at `POST /verify`, set signed HttpOnly cookie, redirect back.

## Why this pattern

- enforcement remains server-side
- no client-side bypass of authorization
- no server-side session table required (stateless signed cookie)

## Cookie requirements

Use a signed cookie containing minimal claims only, for example:

```json
{ "verified": true, "exp": 1700000000, "level": "18+" }
```

Set with:

- `HttpOnly`
- `Secure`
- `SameSite=Lax`
- `Path=/`
- bounded `Max-Age`

## Provider coexistence

If you support more than one verifier, normalize each verification result into the SDK `VerificationAssertion` shape and reuse the same signed-cookie issuance and enforcement logic.

## Framework adapters

First-party framework adapters are available now:

- Express: `/docs/frameworks/express.md`
- Fastify: `/docs/frameworks/fastify.md`
- Hono: `/docs/frameworks/hono.md`
- Nuxt server middleware helper: `/docs/frameworks/nuxt.md`
