# Hono Integration

```ts
import { Hono } from "hono";
import {
  AgeCheckSdk,
  createHonoGateMiddleware,
  createHonoVerifyHandler,
} from "@agecheck/node";

const app = new Hono();

const sdk = new AgeCheckSdk({
  deploymentMode: "production",
  verify: { requiredAge: 18 },
  gate: { headerName: "X-Age-Gate", requiredValue: "true" },
  cookie: { secret: process.env.AGECHECK_COOKIE_SECRET!, cookieName: "agecheck_verified", ttlSeconds: 86400 },
});

app.post("/verify", createHonoVerifyHandler(sdk));
app.use("/restricted/*", createHonoGateMiddleware(sdk, { gatePath: "/ageverify" }));
app.get("/restricted/content", (c) => c.text("Restricted content"));
```
