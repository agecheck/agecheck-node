# Express Integration

```ts
import express from "express";
import {
  AgeCheckSdk,
  createExpressGateMiddleware,
  createExpressVerifyHandler,
} from "@agecheck/node";

const app = express();
app.use(express.json());

const sdk = new AgeCheckSdk({
  deploymentMode: process.env.AGECHECK_DEPLOYMENT_MODE === "demo" ? "demo" : "production",
  verify: { requiredAge: Number(process.env.AGECHECK_REQUIRED_AGE ?? "18") },
  gate: {
    headerName: process.env.AGECHECK_GATE_HEADER_NAME ?? "X-Age-Gate",
    requiredValue: process.env.AGECHECK_GATE_HEADER_REQUIRED_VALUE ?? "true",
  },
  cookie: { secret: process.env.AGECHECK_COOKIE_SECRET!, cookieName: "agecheck_verified", ttlSeconds: 86400 },
});

app.post("/verify", createExpressVerifyHandler(sdk));

app.use("/restricted", createExpressGateMiddleware(sdk, { gatePath: "/ageverify" }));
app.get("/restricted", (_req, res) => {
  res.status(200).send("Restricted content");
});
```

Required environment variables:

```bash
AGECHECK_COOKIE_SECRET=replace_with_32_plus_bytes_random
AGECHECK_DEPLOYMENT_MODE=production
AGECHECK_REQUIRED_AGE=18
AGECHECK_GATE_HEADER_NAME=X-Age-Gate
AGECHECK_GATE_HEADER_REQUIRED_VALUE=true
```
