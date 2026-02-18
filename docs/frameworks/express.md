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
  deploymentMode: "production",
  verify: { requiredAge: 18 },
  gate: { headerName: "X-Age-Gate", requiredValue: "true" },
  cookie: { secret: process.env.AGECHECK_COOKIE_SECRET!, cookieName: "agecheck_verified", ttlSeconds: 86400 },
});

app.post("/verify", createExpressVerifyHandler(sdk));

app.use("/restricted", createExpressGateMiddleware(sdk, { gatePath: "/ageverify" }));
app.get("/restricted", (_req, res) => {
  res.status(200).send("Restricted content");
});
```
