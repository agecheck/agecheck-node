# Existing Site Integration

This guide describes how to add AgeCheck to an existing adult website without redesigning page templates.

## Recommended pattern

1. Keep your existing page rendering code.
2. Add middleware/server guard on protected routes.
3. Redirect unverified users to your gate route (for example `/ageverify`).
4. Verify JWT at `POST /verify`, set signed HttpOnly cookie, redirect back.

## Existing Gate Integration (Provider Mode)

If your site already has a gate and multiple providers, add AgeCheck as one provider option:

1. Keep your gate UI and policy engine unchanged.
2. Generate or forward the provider session identifier (AgeCheck expects `agegateway_session`).
3. For AgeCheck, call `verifyAgeCheckCredential(...)`.
4. For other providers, map result with `normalizeExternalProviderAssertion(...)`.
5. Issue one canonical cookie with `buildSetCookieFromProviderAssertion(...)`.

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

If you support more than one verifier, normalize each verification result into the provider assertion shape and reuse the same signed-cookie issuance and enforcement logic:

```ts
{
  provider: string;
  verified: true;
  level: `${number}+`;
  session: string;
  verifiedAtUnix: number;
  assurance?: string;
}
```

## Framework adapters

First-party framework adapters are available now:

- Express: `/docs/frameworks/express.md`
- Fastify: `/docs/frameworks/fastify.md`
- Hono: `/docs/frameworks/hono.md`
- Nuxt server middleware helper: `/docs/frameworks/nuxt.md`
