# Fastify Integration

Prerequisites: see `/docs/QUICKSTART.md`.

```ts
import Fastify from "fastify";
import {
  AgeCheckSdk,
  createFastifyGateHook,
  createFastifyVerifyHandler,
} from "@agecheck/node";

const fastify = Fastify();

const sdk = new AgeCheckSdk({
  deploymentMode: process.env.AGECHECK_DEPLOYMENT_MODE === "demo" ? "demo" : "production",
  verify: { requiredAge: Number(process.env.AGECHECK_REQUIRED_AGE ?? "18") },
  gate: {
    headerName: process.env.AGECHECK_GATE_HEADER_NAME ?? "X-Age-Gate",
    requiredValue: process.env.AGECHECK_GATE_HEADER_REQUIRED_VALUE ?? "true",
  },
  cookie: { secret: process.env.AGECHECK_COOKIE_SECRET!, cookieName: "agecheck_verified", ttlSeconds: 86400 },
});

fastify.post("/verify", createFastifyVerifyHandler(sdk));
fastify.addHook("preHandler", async (request, reply) => {
  if (!request.url.startsWith("/restricted")) return;
  await createFastifyGateHook(sdk, { gatePath: "/ageverify" })(request, reply);
});

fastify.get("/restricted", async () => "Restricted content");
```
