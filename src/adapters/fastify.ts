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

export interface FastifyRequestLike {
  method?: string;
  url?: string;
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
}

export interface FastifyReplyLike {
  code(statusCode: number): this;
  header(name: string, value: string): this;
  send(payload: unknown): unknown;
  redirect(url: string, statusCode?: number): unknown;
}

export interface FastifyAdapterOptions extends AdapterOptions {
  gatePath?: string;
}

export function createFastifyGateHook(
  sdk: AgeCheckSdk,
  options: FastifyAdapterOptions = {},
): (request: FastifyRequestLike, reply: FastifyReplyLike) => Promise<void> {
  return async (request: FastifyRequestLike, reply: FastifyReplyLike): Promise<void> => {
    const absoluteUrl = toAbsoluteUrl(request.url, request.headers);
    const req = new Request(absoluteUrl, {
      method: request.method ?? "GET",
      headers: toWebHeaders(request.headers),
    });

    const enforcement = await sdk.requireVerifiedOrRedirect(
      req,
      options.gatePath === undefined ? {} : { gatePath: options.gatePath },
    );
    if (enforcement === null) {
      return;
    }

    const location = enforcement.headers.get("location") ?? options.gatePath ?? "/ageverify";
    reply.redirect(location, enforcement.status);
  };
}

export function createFastifyVerifyHandler(
  sdk: AgeCheckSdk,
  options: FastifyAdapterOptions = {},
): (request: FastifyRequestLike, reply: FastifyReplyLike) => Promise<void> {
  return async (request: FastifyRequestLike, reply: FastifyReplyLike): Promise<void> => {
    const outcome = await verifyAndBuildOutcome(sdk, request.body, options);
    if (!outcome.ok) {
      reply.code(outcome.status).send(outcome.body);
      return;
    }

    reply.header("set-cookie", outcome.setCookie).code(200).send(outcome.body);
  };
}
