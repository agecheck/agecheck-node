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

import { describe, expect, it } from "vitest";
import {
  AgeCheckSdk,
  createExpressGateMiddleware,
  createExpressVerifyHandler,
  createFastifyGateHook,
  createFastifyVerifyHandler,
  createHonoGateMiddleware,
  createHonoVerifyHandler,
  createNuxtGateMiddleware,
  createNuxtVerifyHandler,
  type ExpressResponseLike,
  type FastifyReplyLike,
  type HonoContextLike,
  type NuxtEventLike,
} from "../src/index.js";

function makeSdk(): AgeCheckSdk {
  return new AgeCheckSdk({
    deploymentMode: "production",
    gate: {
      headerName: "X-Age-Gate",
      requiredValue: "true",
    },
    cookie: {
      secret: "s".repeat(32),
      cookieName: "agecheck_verified",
      ttlSeconds: 3600,
    },
    verify: {
      requiredAge: 18,
    },
  });
}

describe("express adapter", () => {
  it("redirects when gate is required and cookie missing", async () => {
    const sdk = makeSdk();
    const middleware = createExpressGateMiddleware(sdk, { gatePath: "/ageverify" });

    let redirectedStatus: number | undefined;
    let redirectedLocation: string | undefined;
    let nextCalled = false;
    const response: ExpressResponseLike = {
      status: () => response,
      json: () => response,
      setHeader: () => undefined,
      redirect: (status: number, location: string) => {
        redirectedStatus = status;
        redirectedLocation = location;
      },
    };

    await middleware(
      {
        method: "GET",
        url: "/restricted?a=1",
        headers: {
          host: "example.com",
          "x-age-gate": "true",
        },
      },
      response,
      () => {
        nextCalled = true;
      },
    );

    expect(nextCalled).toBe(false);
    if (redirectedStatus === undefined || redirectedLocation === undefined) {
      throw new Error("expected redirect");
    }
    expect(redirectedStatus).toBe(302);
    expect(redirectedLocation).toContain("/ageverify?redirect=%2Frestricted%3Fa%3D1");
  });

  it("sets signed cookie for provider verification success", async () => {
    const sdk = makeSdk();
    const handler = createExpressVerifyHandler(sdk, {
      providerVerifier: async () => ({
        verified: true,
        provider: "external-provider",
        level: "21+",
        session: "session-123",
      }),
    });

    let statusCode = 0;
    let payload: unknown;
    let setCookieHeader = "";

    const response: ExpressResponseLike = {
      status: (code: number) => {
        statusCode = code;
        return response;
      },
      json: (body: unknown) => {
        payload = body;
        return response;
      },
      setHeader: (name: string, value: string) => {
        if (name.toLowerCase() === "set-cookie") {
          setCookieHeader = value;
        }
      },
      redirect: () => undefined,
    };

    await handler(
      {
        body: {
          provider: "external-provider",
          payload: {
            agegateway_session: "session-123",
          },
          redirect: "/ok",
        },
        headers: {
          host: "example.com",
        },
      },
      response,
      () => undefined,
    );

    expect(statusCode).toBe(200);
    expect(setCookieHeader).toContain("agecheck_verified=");
    expect(payload).toEqual({ verified: true, redirect: "/ok", ageTier: "21+" });
  });
});

describe("fastify adapter", () => {
  it("returns 401 on provider session mismatch", async () => {
    const sdk = makeSdk();
    const handler = createFastifyVerifyHandler(sdk, {
      providerVerifier: async () => ({
        verified: true,
        provider: "external-provider",
        level: "21+",
        session: "wrong-session",
      }),
    });

    let statusCode = 0;
    let sentBody: unknown;

    const reply: FastifyReplyLike = {
      code(code: number) {
        statusCode = code;
        return this;
      },
      header() {
        return this;
      },
      send(payload: unknown) {
        sentBody = payload;
        return payload;
      },
      redirect() {
        return undefined;
      },
    };

    await handler(
      {
        headers: { host: "example.com" },
        body: {
          provider: "external-provider",
          payload: { agegateway_session: "expected-session" },
        },
      },
      reply,
    );

    expect(statusCode).toBe(401);
    expect(sentBody).toMatchObject({ verified: false, code: "session_binding_mismatch" });
  });

  it("redirects when gate is required", async () => {
    const sdk = makeSdk();
    const hook = createFastifyGateHook(sdk, { gatePath: "/ageverify" });

    let redirectedStatus: number | undefined;
    const reply: FastifyReplyLike = {
      code() {
        return this;
      },
      header() {
        return this;
      },
      send() {
        return undefined;
      },
      redirect(location: string, statusCode?: number) {
        void location;
        redirectedStatus = statusCode ?? 302;
        return undefined;
      },
    };

    await hook(
      {
        method: "GET",
        url: "/restricted",
        headers: { host: "example.com", "x-age-gate": "true" },
      },
      reply,
    );

    if (redirectedStatus === undefined) {
      throw new Error("expected redirect");
    }
    expect(redirectedStatus).toBe(302);
  });
});

describe("hono adapter", () => {
  it("builds successful response and set-cookie", async () => {
    const sdk = makeSdk();
    const handler = createHonoVerifyHandler(sdk, {
      providerVerifier: async () => ({
        verified: true,
        provider: "external-provider",
        level: "18+",
        session: "session-1",
      }),
    });

    const headers = new Headers();
    const context: HonoContextLike = {
      req: {
        raw: new Request("https://example.com/verify", { method: "POST" }),
        json: async () => ({
          provider: "external-provider",
          payload: { agegateway_session: "session-1" },
          redirect: "/done",
        }),
      },
      header(name: string, value: string) {
        headers.set(name, value);
      },
      json(payload: unknown, status?: number) {
        return new Response(JSON.stringify(payload), { status: status ?? 200 });
      },
      redirect(location: string, status?: number) {
        return new Response(null, { status: status ?? 302, headers: { location } });
      },
    };

    const result = await handler(context);
    const json = (await result.json()) as Record<string, unknown>;

    expect(result.status).toBe(200);
    expect(json.verified).toBe(true);
    expect(headers.get("set-cookie")).toContain("agecheck_verified=");
  });

  it("redirects from middleware when required", async () => {
    const sdk = makeSdk();
    const middleware = createHonoGateMiddleware(sdk, { gatePath: "/ageverify" });

    const context: HonoContextLike = {
      req: {
        raw: new Request("https://example.com/restricted", {
          headers: { "x-age-gate": "true" },
        }),
        json: async () => ({}),
      },
      header: () => undefined,
      json: (payload: unknown, status?: number) => new Response(JSON.stringify(payload), { status: status ?? 200 }),
      redirect: (location: string, status?: number) => new Response(null, { status: status ?? 302, headers: { location } }),
    };

    const response = await middleware(context, async () => undefined);
    expect(response).toBeInstanceOf(Response);
    expect((response as Response).status).toBe(302);
  });
});

describe("nuxt adapter", () => {
  it("writes verify response and set-cookie to node response", async () => {
    const sdk = makeSdk();
    const handler = createNuxtVerifyHandler(sdk, {
      readBody: async () => ({
        provider: "external-provider",
        payload: { agegateway_session: "nuxt-session" },
      }),
      providerVerifier: async () => ({
        verified: true,
        provider: "external-provider",
        level: "18+",
        session: "nuxt-session",
      }),
    });

    const headers = new Map<string, string>();
    let endedBody = "";
    const event: NuxtEventLike = {
      node: {
        req: {
          method: "POST",
          url: "/verify",
          headers: { host: "example.com" },
        },
        res: {
          statusCode: 0,
          setHeader(name: string, value: string): void {
            headers.set(name.toLowerCase(), value);
          },
          end(body?: string): void {
            endedBody = body ?? "";
          },
        },
      },
    };

    await handler(event);

    expect(event.node?.res.statusCode).toBe(200);
    expect(headers.get("set-cookie")).toContain("agecheck_verified=");
    expect(endedBody).toContain('"verified":true');
  });

  it("sets redirect headers when gate middleware blocks", async () => {
    const sdk = makeSdk();
    const middleware = createNuxtGateMiddleware(sdk, { gatePath: "/ageverify" });

    const headers = new Map<string, string>();
    let ended = false;
    const event: NuxtEventLike = {
      node: {
        req: {
          method: "GET",
          url: "/restricted",
          headers: {
            host: "example.com",
            "x-age-gate": "true",
          },
        },
        res: {
          statusCode: 0,
          setHeader(name: string, value: string): void {
            headers.set(name.toLowerCase(), value);
          },
          end(): void {
            ended = true;
          },
        },
      },
    };

    await middleware(event);

    expect(event.node?.res.statusCode).toBe(302);
    expect(headers.get("location")).toContain("/ageverify?redirect=%2Frestricted");
    expect(ended).toBe(true);
  });
});
