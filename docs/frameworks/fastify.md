# Fastify Integration

```ts
import Fastify from "fastify";
import {
  AgeCheckSdk,
  createFastifyGateHook,
  createFastifyVerifyHandler,
} from "@agecheck/node";

const fastify = Fastify();

const sdk = new AgeCheckSdk({
  deploymentMode: "production",
  verify: { requiredAge: 18 },
  gate: { headerName: "X-Age-Gate", requiredValue: "true" },
  cookie: { secret: process.env.AGECHECK_COOKIE_SECRET!, cookieName: "agecheck_verified", ttlSeconds: 86400 },
});

fastify.post("/verify", createFastifyVerifyHandler(sdk));
fastify.addHook("preHandler", async (request, reply) => {
  if (!request.url.startsWith("/restricted")) return;
  await createFastifyGateHook(sdk, { gatePath: "/ageverify" })(request, reply);
});

fastify.get("/restricted", async () => "Restricted content");
```
