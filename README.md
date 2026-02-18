# AgeCheck Node SDK (`@agecheck/node`)

[![CI](https://github.com/agecheck/agecheck-node/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/agecheck/agecheck-node/actions/workflows/ci.yml)
[![Compatibility](https://github.com/agecheck/agecheck-node/actions/workflows/compatibility.yml/badge.svg?branch=main)](https://github.com/agecheck/agecheck-node/actions/workflows/compatibility.yml)
[![npm](https://img.shields.io/npm/v/%40agecheck%2Fnode?label=npm)](https://www.npmjs.com/package/@agecheck/node)

TypeScript server SDK for age verification, designed to help websites implement compliant age-assurance flows across jurisdictions.

## What this package is for

- enforce gate policy server-side
- verify AgeCheck credentials (`did:web:agecheck.me` and optional demo issuer)
- issue and validate signed HttpOnly verification cookies
- keep provider integration pluggable behind one assertion boundary

## Install

```bash
pnpm add @agecheck/node
```

## Minimal integration path (existing sites)

This is the shortest production path for hostmasters.

1. Build one SDK instance at server startup.
2. Protect routes with `requireVerifiedOrRedirect(...)`.
3. Handle `POST /verify` by verifying JWT + session and setting signed cookie.
4. Trust cookie validation on every protected request.

```ts
import { AgeCheckSdk } from "@agecheck/node";

const sdk = new AgeCheckSdk({
  deploymentMode: "production", // "demo" for demo deployments
  verify: {
    requiredAge: 18,
    allowCustomIssuer: false,
  },
  gate: {
    headerName: "X-Age-Gate",
    requiredValue: "true",
  },
  cookie: {
    secret: process.env.AGECHECK_COOKIE_SECRET!,
    cookieName: "agecheck_verified",
    ttlSeconds: 86400,
  },
});

export async function enforce(request: Request): Promise<Response | null> {
  return sdk.requireVerifiedOrRedirect(request, { gatePath: "/ageverify" });
}

export async function verifyEndpoint(request: Request): Promise<Response> {
  const body = (await request.json()) as {
    jwt?: string;
    payload?: { agegateway_session?: string };
    redirect?: string;
  };

  const result = await sdk.verifyToken(body.jwt ?? "", body.payload?.agegateway_session ?? "");
  if (!result.ok) {
    return Response.json(
      { verified: false, error: "Age validation failed.", code: result.code },
      { status: 401 },
    );
  }

  const setCookie = await sdk.buildSetCookieFromAssertion({
    provider: "agecheck",
    verified: true,
    level: result.ageTier,
    verifiedAtUnix: Math.floor(Date.now() / 1000),
    assurance: "passkey",
  });

  const headers = new Headers({ "content-type": "application/json" });
  headers.append("set-cookie", setCookie);

  return new Response(
    JSON.stringify({ verified: true, redirect: body.redirect ?? "/" }),
    { status: 200, headers },
  );
}
```

## Deployment modes

- `production`
  - accepts production issuer credentials
  - gate is raised only when policy header requires it
- `demo`
  - accepts demo + production issuer credentials
  - gate is always raised

## Provider boundary

AgeCheck is the default provider, but you can normalize other provider results into the same assertion model and keep one cookie pipeline.

```ts
const cookie = await sdk.buildSetCookieFromAssertion({
  provider: "my-provider",
  verified: true,
  level: "21+",
  verifiedAtUnix: Math.floor(Date.now() / 1000),
});
```

## Framework adapters

`@agecheck/node` includes framework adapter helpers:

- `createExpressGateMiddleware`, `createExpressVerifyHandler`
- `createFastifyGateHook`, `createFastifyVerifyHandler`
- `createHonoGateMiddleware`, `createHonoVerifyHandler`
- `createNuxtGateMiddleware`, `createNuxtVerifyHandler`

See `/docs/ADAPTERS.md` for adapter mapping and behavior notes.

## Worker reference

`worker-demo/` is a reference backend implementation (verify endpoint + gate page + cookie endpoints). It is useful for validation and demos, but production adopters should wire the SDK into their own server routes/middleware.

## Existing sites

See `/docs/EXISTING_SITES.md` for the migration pattern that keeps your existing templates/content and moves enforcement into middleware.

## Full hostmaster guide

See `/docs/HOSTMASTER_E2E.md` for the full request lifecycle and production enforcement model.

## Framework compatibility

See `/docs/COMPATIBILITY.md` for latest-framework compatibility coverage and CI validation scope.

## Versioning and releases

See `/docs/VERSIONING.md`.

## Quality gates

```bash
pnpm typecheck
pnpm test
pnpm build
```

## License

Apache-2.0
