# Versioning and Release Policy

## SemVer policy

`@agecheck/node` follows Semantic Versioning.

- `MAJOR`: breaking API/adapter changes
- `MINOR`: backward-compatible adapter/features additions
- `PATCH`: backward-compatible fixes and hardening

## Adapter stability policy

Adapter helper signatures are part of the public API surface. Breaking adapter shape changes require a major version bump.

## Release checklist

1. `pnpm install --frozen-lockfile`
2. `pnpm typecheck`
3. `pnpm test`
4. `pnpm build`
5. bump version
6. tag release
7. publish from CI workflow
