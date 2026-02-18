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

export interface NuxtNodeRequestLike {
  method?: string;
  url?: string;
  headers: Record<string, string | string[] | undefined>;
}

export interface NuxtNodeResponseLike {
  statusCode: number;
  setHeader(name: string, value: string): void;
  end(body?: string): void;
}

export interface NuxtEventLike {
  request?: Request;
  node?: {
    req: NuxtNodeRequestLike;
    res: NuxtNodeResponseLike;
  };
}

export interface NuxtAdapterOptions extends AdapterOptions {
  gatePath?: string;
  readBody: (event: NuxtEventLike) => Promise<unknown>;
}

function getEventRequest(event: NuxtEventLike): Request {
  if (event.request instanceof Request) {
    return event.request;
  }

  const nodeReq = event.node?.req;
  if (!nodeReq) {
    throw new Error("Nuxt event must include request or node.req");
  }

  const absoluteUrl = toAbsoluteUrl(nodeReq.url, nodeReq.headers);
  return new Request(absoluteUrl, {
    method: nodeReq.method ?? "GET",
    headers: toWebHeaders(nodeReq.headers),
  });
}

function getNodeResponse(event: NuxtEventLike): NuxtNodeResponseLike {
  const response = event.node?.res;
  if (!response) {
    throw new Error("Nuxt node response is required for this adapter");
  }
  return response;
}

export function createNuxtGateMiddleware(
  sdk: AgeCheckSdk,
  options: Omit<NuxtAdapterOptions, "readBody"> = {},
): (event: NuxtEventLike) => Promise<void> {
  return async (event: NuxtEventLike): Promise<void> => {
    const request = getEventRequest(event);
    const enforcement = await sdk.requireVerifiedOrRedirect(
      request,
      options.gatePath === undefined ? {} : { gatePath: options.gatePath },
    );
    if (enforcement === null) {
      return;
    }

    const location = enforcement.headers.get("location") ?? options.gatePath ?? "/ageverify";
    const response = getNodeResponse(event);
    response.statusCode = enforcement.status;
    response.setHeader("location", location);
    response.end();
  };
}

export function createNuxtVerifyHandler(
  sdk: AgeCheckSdk,
  options: NuxtAdapterOptions,
): (event: NuxtEventLike) => Promise<void> {
  return async (event: NuxtEventLike): Promise<void> => {
    const body = await options.readBody(event);
    const outcome = await verifyAndBuildOutcome(sdk, body, options);

    const response = getNodeResponse(event);
    response.statusCode = outcome.ok ? 200 : outcome.status;
    if (outcome.ok) {
      response.setHeader("set-cookie", outcome.setCookie);
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify(outcome.body));
      return;
    }

    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify(outcome.body));
  };
}
