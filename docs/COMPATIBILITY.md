# Compatibility Matrix

Last reviewed: February 18, 2026.

This package is framework-runtime agnostic and uses structural adapter contracts. Compatibility is validated by type-checking adapter integration snippets against the latest framework packages in CI.

## Targets

- Express: latest major `5.x`
- Fastify: latest major `5.x`
- Hono: latest major `4.x`
- Nuxt: latest major `4.x`
- Vue: latest major `3.x` (via Nuxt server integration environments)

## What is validated

- Adapter factory signatures compile with current framework types.
- Gate middleware wiring compiles.
- Verify handler wiring compiles.
- Nuxt + Vue latest packages install alongside `@agecheck/node` and compile adapter usage.

## Notes

- `@agecheck/node` adapters avoid hard runtime imports from framework internals.
- `createNuxtVerifyHandler` requires an explicit `readBody` callback so host applications remain in control of Nuxt/H3 body parsing.
