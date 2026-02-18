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
import { toAbsoluteUrl, toWebHeaders, type AdapterOptions, verifyAndBuildOutcome } from "./common.js";

export interface ExpressRequestLike {
  method?: string;
  originalUrl?: string;
  url?: string;
  protocol?: string;
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
}

export interface ExpressResponseLike {
  status(code: number): this;
  json(payload: unknown): this;
  setHeader(name: string, value: string): void;
  redirect(status: number, url: string): void;
}

export type ExpressNext = (error?: unknown) => void;

export interface ExpressAdapterOptions extends AdapterOptions {
  gatePath?: string;
}

export function createExpressGateMiddleware(
  sdk: AgeCheckSdk,
  options: ExpressAdapterOptions = {},
): (req: ExpressRequestLike, res: ExpressResponseLike, next: ExpressNext) => Promise<void> {
  return async (req: ExpressRequestLike, res: ExpressResponseLike, next: ExpressNext): Promise<void> => {
    try {
      const path = req.originalUrl ?? req.url ?? "/";
      const absoluteUrl = toAbsoluteUrl(path, req.headers);
      const request = new Request(absoluteUrl, {
        method: req.method ?? "GET",
        headers: toWebHeaders(req.headers),
      });

      const enforcement = await sdk.requireVerifiedOrRedirect(
        request,
        options.gatePath === undefined ? {} : { gatePath: options.gatePath },
      );
      if (enforcement === null) {
        next();
        return;
      }

      const location = enforcement.headers.get("location") ?? options.gatePath ?? "/ageverify";
      res.redirect(enforcement.status, location);
      return;
    } catch (error: unknown) {
      next(error);
    }
  };
}

export function createExpressVerifyHandler(
  sdk: AgeCheckSdk,
  options: ExpressAdapterOptions = {},
): (req: ExpressRequestLike, res: ExpressResponseLike, next: ExpressNext) => Promise<void> {
  return async (req: ExpressRequestLike, res: ExpressResponseLike, next: ExpressNext): Promise<void> => {
    try {
      const outcome = await verifyAndBuildOutcome(sdk, req.body, options);
      if (!outcome.ok) {
        res.status(outcome.status).json(outcome.body);
        return;
      }

      res.setHeader("set-cookie", outcome.setCookie);
      res.status(200).json(outcome.body);
    } catch (error: unknown) {
      next(error);
    }
  };
}
