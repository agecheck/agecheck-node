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

import type { AgeCheckSdk } from "@agecheck/core";
import { type AdapterOptions, verifyAndBuildOutcome } from "./common.js";

export interface HonoRequestLike {
  raw: Request;
  json(): Promise<unknown>;
}

export interface HonoContextLike {
  req: HonoRequestLike;
  header(name: string, value: string): void;
  json(payload: unknown, status?: number): Response;
  redirect(location: string, status?: number): Response;
}

export interface HonoAdapterOptions extends AdapterOptions {
  gatePath?: string;
}

export function createHonoGateMiddleware(
  sdk: AgeCheckSdk,
  options: HonoAdapterOptions = {},
): (context: HonoContextLike, next: () => Promise<void>) => Promise<Response | void> {
  return async (context: HonoContextLike, next: () => Promise<void>): Promise<Response | void> => {
    const enforcement = await sdk.requireVerifiedOrRedirect(
      context.req.raw,
      options.gatePath === undefined ? {} : { gatePath: options.gatePath },
    );
    if (enforcement === null) {
      await next();
      return;
    }

    const location = enforcement.headers.get("location") ?? options.gatePath ?? "/ageverify";
    return context.redirect(location, enforcement.status);
  };
}

export function createHonoVerifyHandler(
  sdk: AgeCheckSdk,
  options: HonoAdapterOptions = {},
): (context: HonoContextLike) => Promise<Response> {
  return async (context: HonoContextLike): Promise<Response> => {
    const body = await context.req.json();
    const outcome = await verifyAndBuildOutcome(sdk, body, options);
    if (!outcome.ok) {
      return context.json(outcome.body, outcome.status);
    }

    context.header("set-cookie", outcome.setCookie);
    return context.json(outcome.body, 200);
  };
}
