/*
 * AgeCheck-node
 * Copyright (c) 2026 ReallyMe LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import { AgeCheckSdk, verifyAgeToken } from "@agecheck/node";
import type { VerificationAssertion } from "@agecheck/node";

interface Env {
  AGECHECK_COOKIE_SECRET: string;
  AGECHECK_DEPLOYMENT_MODE?: "production" | "demo";
  AGECHECK_REQUIRED_AGE?: string;
  AGECHECK_EASY_AGEGATE?: string;
  AGECHECK_CORS_ALLOWED_ORIGINS?: string;
  DEMO_STATIC: R2Bucket;
}

interface VerifyRequestBody {
  provider?: unknown;
  jwt?: unknown;
  payload?: {
    agegateway_session?: unknown;
  };
  redirect?: unknown;
  providerResult?: {
    verified?: unknown;
    ageTier?: unknown;
    session?: unknown;
    assurance?: unknown;
  };
}

interface ProviderVerifySuccess {
  ok: true;
  assertion: VerificationAssertion;
}

interface ProviderVerifyFailure {
  ok: false;
  code: string;
  message: string;
  detail?: string;
}

type ProviderVerifyResult = ProviderVerifySuccess | ProviderVerifyFailure;

interface JwksProbeResult {
  url: string;
  ok: boolean;
  status?: number;
  kids?: string[];
  error?: string;
}

function renderPublicEntryHtml(redirectPath: string): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="referrer" content="no-referrer" />
  <title>AgeCheck.me</title>
  <style>
    :root{--bg:#0b0d14;--text:#f9fafb;--muted:#cbd5e1;--accent:#7c3aed}
    *{box-sizing:border-box}
    body{margin:0;min-height:100vh;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:var(--text);background:radial-gradient(circle at 20% 0%, #1e1b4b 0%, #0b0d14 48%, #090b11 100%)}
    .overlay{position:fixed;inset:0;z-index:10;display:grid;place-items:center;padding:1rem;background:rgba(5,8,16,.82);backdrop-filter:blur(12px) saturate(.9)}
    .modal{width:min(520px,100%);border-radius:1rem;border:1px solid rgba(255,255,255,.16);background:linear-gradient(180deg,rgba(12,16,30,.95),rgba(9,12,22,.97));padding:clamp(1rem,4vw,1.5rem)}
    .kicker{margin:0;color:#fbbf24;font-size:.75rem;letter-spacing:.08em;text-transform:uppercase}
    .modal h2{margin:.5rem 0 0;font-size:clamp(1.2rem,4vw,1.6rem)}
    .modal p{margin:.7rem 0 0}
    .actions{display:grid;gap:.65rem;margin-top:1rem}
    button{border:0;border-radius:.75rem;padding:.85rem .95rem;font-size:.97rem;font-weight:700;cursor:pointer}
    .primary{color:#fff;background:var(--accent)}
    .secondary{color:var(--muted);background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.16)}
    .hidden{display:none!important}
  </style>
</head>
<body>
  <section id="gate" class="overlay hidden" aria-modal="true" role="dialog"><div class="modal"><p class="kicker">Age Restricted Content</p><h2>Anonymous Age Confirmation Required</h2><p id="status">Confirm your age to continue.</p><div class="actions"><button id="verifyBtn" class="primary" type="button">Confirm My Age</button><button id="retryBtn" class="secondary hidden" type="button">Try Again</button></div></div></section>
  <script src="https://cdn.agecheck.me/agegate/v1/agegate.min.js"></script>
  <script>
    (function(){
      const REDIRECT_URL=${JSON.stringify(redirectPath)};
      const include=["session","pidProvider","verificationMethod","loa"];
      const gate=document.getElementById("gate");
      const status=document.getElementById("status");
      const verifyBtn=document.getElementById("verifyBtn");
      const retryBtn=document.getElementById("retryBtn");
      async function checkSession(){const r=await fetch("/session",{method:"GET",credentials:"include"}); if(!r.ok) throw new Error("session"); const b=await r.json(); return !!(b&&b.verified===true);}
      function showGate(msg){gate.classList.remove("hidden"); status.textContent=msg;}
      async function launch(){
        verifyBtn.disabled=true; retryBtn.classList.add("hidden"); status.textContent="Opening secure AgeCheck verification...";
        if(!window.AgeCheck||typeof window.AgeCheck.launchAgeGate!=="function"){verifyBtn.disabled=false; retryBtn.classList.remove("hidden"); status.textContent="AgeCheck SDK unavailable. Refresh and retry."; return;}
        const session=crypto.randomUUID();
        window.AgeCheck.launchAgeGate({
          include, session,
          onSuccess: async (jwt,payload)=>{
            verifyBtn.disabled=false;
            const s=payload&&typeof payload.agegateway_session==="string"?payload.agegateway_session:session;
            const vr=await fetch("/verify",{method:"POST",credentials:"include",headers:{"Content-Type":"application/json"},body:JSON.stringify({jwt,payload:{agegateway_session:s},redirect:REDIRECT_URL})});
            const vb=await vr.json();
            if(!vr.ok||!vb||vb.verified!==true){retryBtn.classList.remove("hidden"); status.textContent=vb&&typeof vb.error==="string"?vb.error:"Server verification failed."; return;}
            window.location.assign(REDIRECT_URL);
          },
          onFailure: (e)=>{verifyBtn.disabled=false; retryBtn.classList.remove("hidden"); status.textContent=e&&e.message?e.message:"Verification failed.";}
        });
      }
      verifyBtn.addEventListener("click",()=>{launch();});
      retryBtn.addEventListener("click",()=>{launch();});
      checkSession().then(v=>{ if(v){ window.location.assign(REDIRECT_URL); return;} showGate("Confirm your age to continue."); }).catch(()=>{ showGate("Could not check session. You can still verify now."); });
    })();
  </script>
</body>
</html>`;
}

function renderRestrictedPageHtml(expiresAtUnix: number): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="referrer" content="no-referrer" />
  <title>Restricted Content</title>
  <style>
    :root{--bg:#0b0d14;--text:#f9fafb;--muted:#cbd5e1;--accent:#7c3aed;--accent2:#818cf8}
    *{box-sizing:border-box}
    body{margin:0;min-height:100vh;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:var(--text);background:radial-gradient(circle at 20% 0%, #1e1b4b 0%, #0b0d14 48%, #090b11 100%)}
    header{display:flex;justify-content:space-between;align-items:center;padding:14px 16px;background:rgba(3,6,12,.66);border-bottom:1px solid rgba(255,255,255,.08);gap:10px}
    .logo{font-size:1.35rem;font-weight:800}.me{color:var(--accent2)}
    .header-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap;justify-content:flex-end}
    main{padding:18px;display:grid;gap:12px}
    .card{border-radius:16px;border:1px solid rgba(255,255,255,.08);background:rgba(20,25,42,.85);overflow:hidden}
    .media{
      min-height:220px;
      background-image:
        linear-gradient(180deg, rgba(9,12,22,.08), rgba(9,12,22,.55)),
        url("https://images.unsplash.com/photo-1514790193030-c89d266d5a9d?auto=format&fit=crop&w=1200&q=80");
      background-size: cover;
      background-position: center;
      background-repeat: no-repeat;
    }
    .content{padding:14px}
    h1{margin:0 0 8px;font-size:1.5rem}
    p{margin:0;color:var(--muted);line-height:1.45}
    .status{display:flex;gap:8px;align-items:center;margin-top:10px}
    .pill{font-size:.72rem;letter-spacing:.08em;text-transform:uppercase;padding:.36rem .56rem;border-radius:999px;border:1px solid rgba(16,185,129,.45);color:#a7f3d0;background:rgba(3,24,20,.65)}
    .timer{font-size:.8rem;color:var(--muted);white-space:nowrap}
    button{border:1px solid rgba(255,255,255,.2);color:var(--muted);background:rgba(255,255,255,.06);border-radius:999px;font-size:.72rem;text-transform:uppercase;letter-spacing:.07em;padding:.42rem .65rem;cursor:pointer}
  </style>
</head>
<body>
  <header>
    <div class="logo">AgeCheck<span class="me">.me</span></div>
    <div class="header-actions">
      <span class="pill">Verified</span>
      <span class="timer" id="remaining"></span>
      <button id="resetBtn" type="button">Reset Verification</button>
    </div>
  </header>
  <main>
    <section class="card">
      <div class="media" role="img" aria-label="Restricted content background"></div>
      <div class="content">
        <h1>Age Restricted Content</h1>
        <p>Access granted. This content is served only after server-side signed cookie validation.</p>
      </div>
    </section>
  </main>
  <script>
    const EXPIRES_AT=${expiresAtUnix};
    function formatRemaining(seconds){
      if(seconds<=0) return "Session expired";
      const h=Math.floor(seconds/3600), m=Math.floor((seconds%3600)/60);
      return h>0 ? h+"h "+m+"m remaining" : m+"m remaining";
    }
    function updateRemaining(){
      const now=Math.floor(Date.now()/1000);
      const el=document.getElementById("remaining");
      if(!el) return;
      el.textContent=formatRemaining(EXPIRES_AT-now);
    }
    updateRemaining();
    setInterval(updateRemaining, 15000);
    document.getElementById("resetBtn").addEventListener("click", async () => {
      try { await fetch("/session/reset", { method: "POST" }); } finally { window.location.assign("/"); }
    });
  </script>
</body>
</html>`;
}

function json(status: number, body: unknown, headers: HeadersInit = {}): Response {
  const merged = new Headers(headers);
  merged.set("content-type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(body), {
    status,
    headers: merged,
  });
}

function cacheControlForStaticPath(pathname: string): string {
  if (pathname === "/.well-known/jwks.json") {
    // Signature keys may rotate; keep this short-lived.
    return "public, max-age=300, stale-while-revalidate=60";
  }
  if (pathname === "/.well-known/did.json") {
    // DID document changes infrequently but should refresh quicker than contexts.
    return "public, max-age=3600, stale-while-revalidate=300";
  }
  if (pathname.startsWith("/credentials/")) {
    // Versioned contexts should be immutable and aggressively cached.
    return "public, max-age=31536000, immutable";
  }
  // Default for other static trust artifacts.
  return "public, max-age=86400, stale-while-revalidate=3600";
}

function inferStaticContentType(pathname: string): string {
  if (pathname.endsWith(".jsonld")) return "application/json; charset=utf-8";
  if (pathname.endsWith(".json")) return "application/json; charset=utf-8";
  return "application/octet-stream";
}

function parseAllowedCorsOrigins(raw: string | undefined, requestOrigin: string): Set<string> {
  const out = new Set<string>();
  out.add(requestOrigin);
  out.add("https://demo.agecheck.me");
  if (typeof raw === "string" && raw.trim().length > 0) {
    for (const token of raw.split(",")) {
      const value = token.trim();
      if (value.length > 0) {
        out.add(value);
      }
    }
  }
  return out;
}

function buildCorsHeaders(request: Request, env: Env): Headers {
  const headers = new Headers();
  const origin = request.headers.get("origin");
  if (!origin) {
    return headers;
  }

  const requestOrigin = new URL(request.url).origin;
  const allowed = parseAllowedCorsOrigins(env.AGECHECK_CORS_ALLOWED_ORIGINS, requestOrigin);
  if (!allowed.has(origin)) {
    return headers;
  }

  headers.set("access-control-allow-origin", origin);
  headers.set("access-control-allow-methods", "GET, POST, OPTIONS");
  headers.set("access-control-allow-headers", "content-type");
  headers.set("access-control-allow-credentials", "true");
  headers.set("access-control-max-age", "600");
  headers.set("vary", "Origin");
  return headers;
}

function makeClearedCookieHeader(cookieName: string, domain?: string): string {
  const domainPart = typeof domain === "string" && domain.length > 0 ? `; Domain=${domain}` : "";
  return `${cookieName}=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT${domainPart}; HttpOnly; Secure; SameSite=Lax`;
}

function normalizeRedirect(rawRedirect: unknown): string {
  if (typeof rawRedirect !== "string" || rawRedirect.length === 0) {
    return "/protected";
  }

  try {
    const parsed = new URL(rawRedirect, "https://example.invalid");
    if (parsed.origin !== "https://example.invalid") {
      return "/protected";
    }

    const path = parsed.pathname.startsWith("/") ? parsed.pathname : "/protected";
    const query = parsed.search ?? "";
    return `${path}${query}`;
  } catch {
    return "/protected";
  }
}

function parseAgeTierValue(level: string): number | null {
  const match = level.match(/^([1-9]\d*)\+$/);
  if (!match) {
    return null;
  }
  const parsed = Number.parseInt(match[1], 10);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    return null;
  }
  return parsed;
}

async function probeJwks(url: string): Promise<JwksProbeResult> {
  try {
    const response = await fetch(url, { method: "GET" });
    const status = response.status;
    if (!response.ok) {
      return { url, ok: false, status, error: `HTTP ${status}` };
    }

    const payload = (await response.json()) as unknown;
    if (!payload || typeof payload !== "object" || !("keys" in payload) || !Array.isArray((payload as { keys: unknown }).keys)) {
      return { url, ok: false, status, error: "Invalid JWKS payload shape." };
    }

    const kids = ((payload as { keys: Array<{ kid?: unknown }> }).keys)
      .map((entry) => (typeof entry.kid === "string" ? entry.kid : ""))
      .filter((kid) => kid.length > 0);

    return { url, ok: true, status, kids };
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Unknown fetch error.";
    return { url, ok: false, error: message };
  }
}

function resolveDeploymentMode(env: Env): "production" | "demo" {
  const deploymentModeRaw = env.AGECHECK_DEPLOYMENT_MODE ?? "production";
  if (deploymentModeRaw !== "production" && deploymentModeRaw !== "demo") {
    throw new Error("AGECHECK_DEPLOYMENT_MODE must be production or demo.");
  }
  return deploymentModeRaw;
}

function createSdk(env: Env, deploymentMode: "production" | "demo"): AgeCheckSdk {
  const requiredAge = Number.parseInt(env.AGECHECK_REQUIRED_AGE ?? "18", 10);

  return new AgeCheckSdk({
    deploymentMode,
    verify: {
      allowCustomIssuer: false,
      deploymentMode,
      requiredAge,
    },
    gate: {
      headerName: "X-Age-Gate",
      requiredValue: "true",
    },
    cookie: {
      secret: env.AGECHECK_COOKIE_SECRET,
      cookieName: "agecheck_verified",
      ttlSeconds: 86400,
    },
  });
}

async function verifyWithAgeCheck(
  sdk: AgeCheckSdk,
  env: Env,
  deploymentMode: "production" | "demo",
  requiredAge: number,
  jwt: string,
  expectedSession: string | undefined,
): Promise<ProviderVerifyResult> {
  if (deploymentMode === "demo") {
    const localJwksObject = await env.DEMO_STATIC.get(".well-known/jwks.json");
    if (localJwksObject === null) {
      return {
        ok: false,
        code: "verify_failed",
        message: "Age validation failed.",
        detail: "Demo JWKS was not found in DEMO_STATIC at .well-known/jwks.json.",
      };
    }

    let localJwks: unknown;
    try {
      localJwks = await localJwksObject.json();
    } catch {
      return {
        ok: false,
        code: "verify_failed",
        message: "Age validation failed.",
        detail: "Demo JWKS could not be parsed from DEMO_STATIC.",
      };
    }

    const verify = await verifyAgeToken({
      jwt,
      expectedSession,
      requireSessionBinding: true,
      config: {
        allowCustomIssuer: true,
        deploymentMode: "demo",
        requiredAge,
        issuer: ["did:web:demo.agecheck.me", "did:web:agecheck.me"],
        localJwks: localJwks as { keys: unknown[] },
      },
    });
    if (!verify.ok) {
      return {
        ok: false,
        code: verify.code,
        message: verify.message,
        detail: verify.detail,
      };
    }
    return {
      ok: true,
      assertion: {
        provider: "agecheck",
        level: verify.ageTier,
        verified: true,
        verifiedAtUnix: Math.floor(Date.now() / 1000),
        assurance: "passkey",
      },
    };
  }

  const verify = await sdk.verifyToken(jwt, expectedSession);
  if (!verify.ok) {
    return {
      ok: false,
      code: verify.code,
      message: verify.message,
      detail: verify.detail,
    };
  }
  return {
    ok: true,
    assertion: {
      provider: "agecheck",
      level: verify.ageTier,
      verified: true,
      verifiedAtUnix: Math.floor(Date.now() / 1000),
      assurance: "passkey",
    },
  };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (!env.AGECHECK_COOKIE_SECRET || env.AGECHECK_COOKIE_SECRET.length < 32) {
      return json(500, { error: "AGECHECK_COOKIE_SECRET must be configured with at least 32 bytes." });
    }

    let sdk: AgeCheckSdk;
    let deploymentMode: "production" | "demo";
    try {
      deploymentMode = resolveDeploymentMode(env);
      sdk = createSdk(env, deploymentMode);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Invalid worker configuration.";
      return json(500, { error: message });
    }
    const url = new URL(request.url);
    const corsHeaders = buildCorsHeaders(request, env);

    if (
      (request.method === "GET" || request.method === "HEAD") &&
      (url.pathname.startsWith("/.well-known/") || url.pathname.startsWith("/credentials/"))
    ) {
      const key = url.pathname.slice(1);
      const object = await env.DEMO_STATIC.get(key);
      if (object === null) {
        return new Response("Not found", { status: 404 });
      }

      const etag = object.httpEtag;
      const ifNoneMatch = request.headers.get("if-none-match");
      if (typeof ifNoneMatch === "string" && ifNoneMatch.trim() === etag) {
        return new Response(null, {
          status: 304,
          headers: {
            etag,
            "cache-control": cacheControlForStaticPath(url.pathname),
            vary: "Accept-Encoding",
          },
        });
      }

      const headers = new Headers();
      object.writeHttpMetadata(headers);
      // Force canonical content types for trust artifacts to avoid download behavior
      // when R2 object metadata was uploaded with application/octet-stream.
      headers.set("content-type", inferStaticContentType(url.pathname));
      headers.set("x-content-type-options", "nosniff");
      headers.set("content-disposition", "inline");
      headers.set("etag", etag);
      headers.set("cache-control", cacheControlForStaticPath(url.pathname));
      headers.set("vary", "Accept-Encoding");

      const body = request.method === "HEAD" ? null : object.body;
      return new Response(body, { headers });
    }

    if (
      (
        url.pathname === "/verify" ||
        url.pathname === "/verify/provider" ||
        url.pathname === "/session" ||
        url.pathname === "/session/reset" ||
        url.pathname === "/restricted-content"
      ) &&
      request.method === "OPTIONS"
    ) {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    if (url.pathname === "/health") {
      const expectedIssuers =
        deploymentMode === "demo"
          ? ["did:web:demo.agecheck.me", "did:web:agecheck.me"]
          : ["did:web:agecheck.me"];
      const jwksUrls =
        deploymentMode === "demo"
          ? [
              "https://demo.agecheck.me/.well-known/jwks.json",
              "https://agecheck.me/.well-known/jwks.json",
            ]
          : ["https://agecheck.me/.well-known/jwks.json"];

      const verbose = url.searchParams.get("verbose") === "1";
      const probes = verbose
        ? await Promise.all(jwksUrls.map((jwksUrl) => probeJwks(jwksUrl)))
        : undefined;

      return json(200, {
        ok: true,
        deploymentMode,
        expectedIssuers,
        jwksUrls,
        unixTime: Math.floor(Date.now() / 1000),
        jwksProbes: probes,
      });
    }

    if (url.pathname === "/" && request.method === "GET") {
      return new Response(renderPublicEntryHtml("/restricted-page"), {
        headers: { "content-type": "text/html; charset=utf-8", "referrer-policy": "no-referrer" },
      });
    }

    if (url.pathname === "/gate" && request.method === "GET") {
      const redirect = normalizeRedirect(url.searchParams.get("redirect"));
      const html = renderPublicEntryHtml(redirect);
      return new Response(html, {
        headers: { "content-type": "text/html; charset=utf-8", "referrer-policy": "no-referrer" },
      });
    }

    if (url.pathname === "/verify" && request.method === "POST") {
      let body: VerifyRequestBody;
      try {
        body = (await request.json()) as VerifyRequestBody;
      } catch {
        return json(400, { verified: false, error: "Invalid JSON" }, corsHeaders);
      }

      if (typeof body.jwt !== "string" || body.jwt.length === 0) {
        return json(400, { verified: false, error: "Missing jwt" }, corsHeaders);
      }

      const expectedSession =
        body.payload && typeof body.payload.agegateway_session === "string"
          ? body.payload.agegateway_session
          : undefined;

      const provider = typeof body.provider === "string" ? body.provider : "agecheck";
      let providerResult: ProviderVerifyResult;
      if (provider === "agecheck") {
        providerResult = await verifyWithAgeCheck(
          sdk,
          env,
          deploymentMode,
          Number.parseInt(env.AGECHECK_REQUIRED_AGE ?? "18", 10),
          body.jwt,
          expectedSession,
        );
      } else {
        providerResult = {
          ok: false,
          code: "unsupported_provider",
          message: "Unsupported verification provider.",
        };
      }
      if (!providerResult.ok) {
        return json(401, {
          verified: false,
          error: providerResult.message,
          code: providerResult.code,
          ...(typeof providerResult.detail === "string" ? { detail: providerResult.detail } : {}),
        }, corsHeaders);
      }

      const redirect = normalizeRedirect(body.redirect);
      const responseHeaders: Record<string, string> = {
        ...Object.fromEntries(corsHeaders.entries()),
      };
      responseHeaders["set-cookie"] = await sdk.buildSetCookieFromAssertion(providerResult.assertion);

      return json(
        200,
        {
          verified: true,
          redirect,
          ageTier: providerResult.assertion.level,
          provider: providerResult.assertion.provider,
        },
        responseHeaders,
      );
    }

    if (url.pathname === "/verify/provider" && request.method === "POST") {
      let body: VerifyRequestBody;
      try {
        body = (await request.json()) as VerifyRequestBody;
      } catch {
        return json(400, { verified: false, error: "Invalid JSON" }, corsHeaders);
      }

      const provider = typeof body.provider === "string" && body.provider.length > 0
        ? body.provider
        : "provider";
      if (provider === "agecheck") {
        return json(400, {
          verified: false,
          error: "Unsupported verification provider.",
          code: "unsupported_provider",
        }, corsHeaders);
      }

      const expectedSession =
        body.payload && typeof body.payload.agegateway_session === "string"
          ? body.payload.agegateway_session
          : undefined;
      const providerResult = body.providerResult;
      if (!providerResult || typeof providerResult !== "object") {
        return json(400, { verified: false, error: "Missing providerResult." }, corsHeaders);
      }

      if (providerResult.verified !== true) {
        return json(401, { verified: false, error: "Provider verification failed." }, corsHeaders);
      }

      if (typeof providerResult.ageTier !== "string") {
        return json(400, { verified: false, error: "Missing provider age tier." }, corsHeaders);
      }
      const ageTierValue = parseAgeTierValue(providerResult.ageTier);
      const requiredAge = Number.parseInt(env.AGECHECK_REQUIRED_AGE ?? "18", 10);
      if (ageTierValue === null || ageTierValue < requiredAge) {
        return json(401, { verified: false, error: "Insufficient age tier." }, corsHeaders);
      }

      if (typeof expectedSession !== "string" || typeof providerResult.session !== "string") {
        return json(401, { verified: false, error: "Missing required session binding." }, corsHeaders);
      }
      if (providerResult.session !== expectedSession) {
        return json(401, { verified: false, error: "Session binding mismatch." }, corsHeaders);
      }

      const redirect = normalizeRedirect(body.redirect);
      const assertion: VerificationAssertion = {
        provider,
        level: providerResult.ageTier,
        verified: true,
        verifiedAtUnix: Math.floor(Date.now() / 1000),
        assurance: typeof providerResult.assurance === "string" && providerResult.assurance.length > 0
          ? providerResult.assurance
          : "external",
      };

      const responseHeaders: Record<string, string> = {
        ...Object.fromEntries(corsHeaders.entries()),
      };
      responseHeaders["set-cookie"] = await sdk.buildSetCookieFromAssertion(assertion);

      return json(200, {
        verified: true,
        redirect,
        ageTier: assertion.level,
        provider: assertion.provider,
      }, responseHeaders);
    }

    if (url.pathname === "/session" && request.method === "GET") {
      const verified = await sdk.getVerifiedCookiePayload(request);
      if (verified === null) {
        return json(200, { verified: false }, corsHeaders);
      }
      const subject = verified.vc && typeof verified.vc === "object"
        ? (verified.vc as { credentialSubject?: unknown }).credentialSubject
        : undefined;
      const ageTier = subject && typeof subject === "object"
        ? (subject as { ageTier?: unknown }).ageTier
        : undefined;
      const expiresAt = typeof verified.exp === "number" ? verified.exp : null;
      const now = Math.floor(Date.now() / 1000);
      return json(
        200,
        {
          verified: true,
          ageTier: typeof ageTier === "string" ? ageTier : null,
          expiresAt,
          remainingSeconds: typeof expiresAt === "number" ? Math.max(0, expiresAt - now) : null,
        },
        corsHeaders,
      );
    }

    if (url.pathname === "/session/reset" && request.method === "POST") {
      const headers = new Headers(corsHeaders);
      // Clear both host-only and legacy parent-domain variants.
      headers.append("set-cookie", makeClearedCookieHeader("agecheck_verified"));
      headers.append("set-cookie", makeClearedCookieHeader("agecheck_verified", ".agecheck.me"));
      return new Response(JSON.stringify({ cleared: true }), {
        status: 200,
        headers,
      });
    }

    if (url.pathname === "/restricted-content" && request.method === "GET") {
      const redirect = await sdk.requireVerifiedOrRedirect(request, {
        gatePath: "/gate",
        redirectTo: "/restricted-page",
      });
      if (redirect !== null) {
        return redirect;
      }
      return Response.redirect(`${url.origin}/restricted-page`, 302);
    }

    if (url.pathname === "/restricted-page" && request.method === "GET") {
      const redirect = await sdk.requireVerifiedOrRedirect(request, {
        gatePath: "/gate",
        redirectTo: "/restricted-page",
      });
      if (redirect !== null) {
        return redirect;
      }
      const verified = await sdk.getVerifiedCookiePayload(request);
      const expiresAt = verified && typeof verified.exp === "number" ? verified.exp : Math.floor(Date.now() / 1000);
      return new Response(renderRestrictedPageHtml(expiresAt), {
        headers: { "content-type": "text/html; charset=utf-8", "referrer-policy": "no-referrer" },
      });
    }

    if (url.pathname === "/protected" && request.method === "GET") {
      const redirect = await sdk.requireVerifiedOrRedirect(request, {
        gatePath: "/gate",
        redirectTo: "/restricted-page",
      });
      if (redirect !== null) {
        return redirect;
      }
      return Response.redirect(`${url.origin}/restricted-page`, 302);
    }

    if (request.method === "GET") {
      const redirect = await sdk.requireVerifiedOrRedirect(request, {
        gatePath: "/gate",
        redirectTo: "/restricted-page",
      });
      if (redirect !== null) {
        return redirect;
      }
      return Response.redirect(`${url.origin}/restricted-page`, 302);
    }

    return json(404, { error: "Not found" });
  },
};
