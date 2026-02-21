# Hono Integration

Prerequisites: see `/docs/QUICKSTART.md`.

```ts
import { Hono } from "hono";
import {
  AgeCheckSdk,
  createHonoGateMiddleware,
  createHonoVerifyHandler,
} from "@agecheck/node";

const app = new Hono();

const sdk = new AgeCheckSdk({
  deploymentMode: process.env.AGECHECK_DEPLOYMENT_MODE === "demo" ? "demo" : "production",
  verify: { requiredAge: Number(process.env.AGECHECK_REQUIRED_AGE ?? "18") },
  gate: {
    headerName: process.env.AGECHECK_GATE_HEADER_NAME ?? "X-Age-Gate",
    requiredValue: process.env.AGECHECK_GATE_HEADER_REQUIRED_VALUE ?? "true",
  },
  cookie: { secret: process.env.AGECHECK_COOKIE_SECRET!, cookieName: "agecheck_verified", ttlSeconds: 86400 },
});

app.post("/verify", createHonoVerifyHandler(sdk));
app.use("/restricted/*", createHonoGateMiddleware(sdk, { gatePath: "/ageverify" }));
app.get("/restricted/content", (c) => c.text("Restricted content"));
```
