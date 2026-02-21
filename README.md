# AgeCheck Node SDK (`@agecheck/node`)

[![CI](https://github.com/agecheck/agecheck-node/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/agecheck/agecheck-node/actions/workflows/ci.yml)
[![Compatibility](https://github.com/agecheck/agecheck-node/actions/workflows/compatibility.yml/badge.svg?branch=main&event=push)](https://github.com/agecheck/agecheck-node/actions/workflows/compatibility.yml)
[![npm](https://img.shields.io/npm/v/%40agecheck%2Fnode?label=npm)](https://www.npmjs.com/package/@agecheck/node)

TypeScript server SDK for age verification, designed to help websites implement compliant age-assurance flows across jurisdictions.

## What this package is for

- enforce gate policy server-side
- verify AgeCheck credentials (`did:web:agecheck.me` and optional demo issuer)
- issue and validate signed HttpOnly verification cookies
- support Existing Gate Integration and multi-provider coexistence

## Install

```bash
pnpm add @agecheck/node
```

Quickstart: see `/docs/QUICKSTART.md`.

## Supported integration modes

1. Managed gate mode: use AgeCheck gate route + verify route + signed cookie.
2. Existing Gate Integration: keep your existing gate and add AgeCheck as one provider option.
3. Hybrid mode: use AgeCheck gate while also supporting other providers in Provider Mode.

All modes converge into one normalized provider assertion and one signed cookie pipeline.

## 5-minute Express setup (recommended)

```ts
import express from "express";
import { AgeCheckSdk, createExpressGateMiddleware, createExpressVerifyHandler } from "@agecheck/node";

const app = express();
app.use(express.json());

const sdk = new AgeCheckSdk({
  deploymentMode: (process.env.AGECHECK_DEPLOYMENT_MODE === "demo" ? "demo" : "production"),
  verify: {
    requiredAge: Number(process.env.AGECHECK_REQUIRED_AGE ?? "18"),
    allowCustomIssuer: false,
  },
  gate: {
    headerName: process.env.AGECHECK_GATE_HEADER_NAME ?? "X-Age-Gate",
    requiredValue: process.env.AGECHECK_GATE_HEADER_REQUIRED_VALUE ?? "true",
  },
  cookie: {
    secret: process.env.AGECHECK_COOKIE_SECRET!,
    cookieName: "agecheck_verified",
    ttlSeconds: 86400,
  },
});

app.post("/verify", createExpressVerifyHandler(sdk));
app.use("/restricted", createExpressGateMiddleware(sdk, { gatePath: "/ageverify" }));
```

This route pair handles token verification and signed verification cookie issuance.
Most hostmasters should not call `buildSetCookieFromAssertion(...)` directly.

## Existing Gate Integration (Provider Mode)

Use these helpers when a hostmaster already has a gate flow and wants to add AgeCheck as a provider:

```ts
import {
  AgeCheckSdk,
  buildSetCookieFromProviderAssertion,
  normalizeExternalProviderAssertion,
  verifyAgeCheckCredential,
  type ProviderVerificationResult,
} from "@agecheck/node";

const sdk = new AgeCheckSdk({
  deploymentMode: "production",
  verify: { requiredAge: 18 },
  cookie: { secret: process.env.AGECHECK_COOKIE_SECRET! },
});

export async function verifyProviderEndpoint(body: {
  provider?: string;
  jwt?: string;
  payload?: { agegateway_session?: string };
  redirect?: string;
}): Promise<Response> {
  const expectedSession = body.payload?.agegateway_session;
  if (typeof expectedSession !== "string" || expectedSession.length === 0) {
    return Response.json({ verified: false, code: "invalid_input", error: "Missing session." }, { status: 400 });
  }

  let assertion: ProviderVerificationResult;
  if ((body.provider ?? "agecheck") === "agecheck") {
    assertion = await verifyAgeCheckCredential(sdk, {
      jwt: body.jwt ?? "",
      expectedSession,
      assurance: "passkey",
    });
  } else {
    const externalResult: ProviderVerificationResult = await verifyOtherProvider(body);
    assertion = normalizeExternalProviderAssertion(externalResult, expectedSession);
  }

  if (!assertion.verified) {
    return Response.json(
      { verified: false, code: assertion.code, error: assertion.message, detail: assertion.detail },
      { status: 401 },
    );
  }

  const setCookie = await buildSetCookieFromProviderAssertion(sdk, assertion);
  return new Response(JSON.stringify({ verified: true, redirect: body.redirect ?? "/" }), {
    status: 200,
    headers: { "content-type": "application/json", "set-cookie": setCookie },
  });
}
```

## Deployment modes

- `production`
  - accepts production issuer credentials
  - gate is raised only when policy header requires it
- `demo`
  - accepts demo + production issuer credentials
  - gate is always raised

## Provider assertion contract

Provider results normalize to this shape:

```ts
{
  provider: string;
  verified: true;
  level: "18+" | "21+" | `${number}+`;
  session: string; // UUID
  verifiedAtUnix: number;
  assurance?: string;
  verificationType?: "passkey" | "oid4vp" | "other";
  evidenceType?: "webauthn_assertion" | "sd_jwt" | "zk_attestation" | "other";
  providerTransactionId?: string;
  loa?: string;
}
```

This keeps provider internals isolated while preserving one site-level cookie and enforcement model.
`payload.agegateway_session` and provider assertion `session` are treated as required UUID values.

## Framework adapters

`@agecheck/node` includes framework adapter helpers:

- `createExpressGateMiddleware`, `createExpressVerifyHandler`
- `createFastifyGateHook`, `createFastifyVerifyHandler`
- `createHonoGateMiddleware`, `createHonoVerifyHandler`
- `createNuxtGateMiddleware`, `createNuxtVerifyHandler`

See `/docs/ADAPTERS.md` for adapter mapping and behavior notes.

## Troubleshooting

If you see:

```json
{
  "verified": false,
  "code": "verify_failed",
  "error": "Failed to issue verification cookie"
}
```

check:
- Node runtime is `>=20`
- `AGECHECK_COOKIE_SECRET` is present in the running process and at least 32 bytes
- `payload.agegateway_session` is a UUID
- your verify route is using adapter helpers (`createExpressVerifyHandler` or equivalent)

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
