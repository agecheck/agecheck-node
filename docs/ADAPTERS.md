# Framework Adapters

`@agecheck/node` provides framework-focused helpers while keeping all verification/cookie logic in the shared core.

## Express

- `createExpressGateMiddleware(sdk, options)`
- `createExpressVerifyHandler(sdk, options)`

## Fastify

- `createFastifyGateHook(sdk, options)`
- `createFastifyVerifyHandler(sdk, options)`

## Hono

- `createHonoGateMiddleware(sdk, options)`
- `createHonoVerifyHandler(sdk, options)`

## Nuxt (server)

- `createNuxtGateMiddleware(sdk, options)`
- `createNuxtVerifyHandler(sdk, { readBody, ...options })`

`readBody` is passed in by the host app so the adapter has no hard dependency on Nuxt/H3 runtime modules.

## Provider coexistence

All adapters support the same provider boundary:

- default provider: `agecheck`
- custom providers: pass `providerVerifier` in adapter options

Provider verifier output is normalized into a single signed-cookie issuance path, so enforcement logic remains identical across providers.

Provider verifier success shape:

```ts
{
  verified: true;
  provider: string;
  level: `${number}+`;
  session: string; // UUID
  verifiedAtUnix?: number;
  assurance?: string;
}
```

`session` is required and must be a UUID. `payload.agegateway_session` is required and must match the provider `session`.

## End-to-end deployment docs

- Hostmaster flow: `/docs/HOSTMASTER_E2E.md`
- Existing-site migration: `/docs/EXISTING_SITES.md`
- Compatibility matrix: `/docs/COMPATIBILITY.md`
- Versioning and release policy: `/docs/VERSIONING.md`
