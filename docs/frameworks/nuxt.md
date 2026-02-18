# Nuxt Server Integration

```ts
// server/middleware/agecheck.ts
import {
  AgeCheckSdk,
  createNuxtGateMiddleware,
} from "@agecheck/node";

const sdk = new AgeCheckSdk({
  deploymentMode: "production",
  verify: { requiredAge: 18 },
  gate: { headerName: "X-Age-Gate", requiredValue: "true" },
  cookie: { secret: process.env.AGECHECK_COOKIE_SECRET!, cookieName: "agecheck_verified", ttlSeconds: 86400 },
});

const guard = createNuxtGateMiddleware(sdk, { gatePath: "/ageverify" });

export default defineEventHandler(async (event) => {
  if (!event.path.startsWith("/restricted")) return;
  await guard(event);
});
```

```ts
// server/api/verify.post.ts
import { readBody } from "h3";
import {
  AgeCheckSdk,
  createNuxtVerifyHandler,
} from "@agecheck/node";

const sdk = new AgeCheckSdk({
  deploymentMode: "production",
  verify: { requiredAge: 18 },
  gate: { headerName: "X-Age-Gate", requiredValue: "true" },
  cookie: { secret: process.env.AGECHECK_COOKIE_SECRET!, cookieName: "agecheck_verified", ttlSeconds: 86400 },
});

const verifyHandler = createNuxtVerifyHandler(sdk, {
  readBody: (event) => readBody(event as any),
});

export default defineEventHandler(async (event) => {
  await verifyHandler(event as any);
});
```
