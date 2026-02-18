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

import { AgeCheckError, ErrorCode, type AgeCheckSdk, type VerificationAssertion } from "@agecheck/core";

export interface AdapterVerifyBody {
  provider?: string;
  jwt?: string;
  payload?: {
    agegateway_session?: string;
  };
  redirect?: string;
}

export interface ProviderVerificationSuccess {
  verified: true;
  provider: string;
  level: string;
  session: string;
  verifiedAtUnix?: number;
  assurance?: string;
}

export interface ProviderVerificationFailure {
  verified: false;
  code: string;
  message: string;
  detail?: string;
}

export type ProviderVerificationResult = ProviderVerificationSuccess | ProviderVerificationFailure;

export type ProviderVerifier = (body: AdapterVerifyBody) => Promise<ProviderVerificationResult>;

export interface AdapterOptions {
  gatePath?: string;
  providerVerifier?: ProviderVerifier;
}

export interface VerificationSuccessResponse {
  verified: true;
  redirect: string;
  ageTier: string;
}

export interface VerificationFailureResponse {
  verified: false;
  error: string;
  code: string;
  detail?: string;
}

export interface VerifyOutcomeSuccess {
  ok: true;
  setCookie: string;
  body: VerificationSuccessResponse;
}

export interface VerifyOutcomeFailure {
  ok: false;
  status: number;
  body: VerificationFailureResponse;
}

export type VerifyOutcome = VerifyOutcomeSuccess | VerifyOutcomeFailure;

export function normalizeRedirect(raw: string | undefined): string {
  if (typeof raw !== "string" || raw.length === 0) {
    return "/";
  }

  try {
    const parsed = new URL(raw, "https://example.invalid");
    if (parsed.origin !== "https://example.invalid") {
      return "/";
    }
    return `${parsed.pathname}${parsed.search}`;
  } catch {
    return "/";
  }
}

export function getHeaderValue(
  headers: Readonly<Record<string, string | string[] | undefined>>,
  key: string,
): string | undefined {
  const direct = headers[key] ?? headers[key.toLowerCase()];
  if (Array.isArray(direct)) {
    return direct.length > 0 ? direct[0] : undefined;
  }
  return direct;
}

export function toWebHeaders(headers: Readonly<Record<string, string | string[] | undefined>>): Headers {
  const out = new Headers();

  for (const [key, raw] of Object.entries(headers)) {
    if (raw === undefined) {
      continue;
    }

    if (Array.isArray(raw)) {
      const values = raw.filter((value): value is string => typeof value === "string");
      if (values.length === 0) {
        continue;
      }
      const separator = key.toLowerCase() === "cookie" ? "; " : ", ";
      out.set(key, values.join(separator));
      continue;
    }

    out.set(key, raw);
  }

  return out;
}

export function toAbsoluteUrl(pathOrUrl: string | undefined, headers: Readonly<Record<string, string | string[] | undefined>>): string {
  const raw = typeof pathOrUrl === "string" && pathOrUrl.length > 0 ? pathOrUrl : "/";
  if (raw.startsWith("http://") || raw.startsWith("https://")) {
    return raw;
  }

  const forwardedProtoRaw = getHeaderValue(headers, "x-forwarded-proto");
  const forwardedProto =
    typeof forwardedProtoRaw === "string" ? forwardedProtoRaw.split(",")[0]?.trim().toLowerCase() : undefined;
  const protocol = forwardedProto === "http" || forwardedProto === "https" ? forwardedProto : "https";

  const forwardedHostRaw = getHeaderValue(headers, "x-forwarded-host");
  const forwardedHost = typeof forwardedHostRaw === "string" ? forwardedHostRaw.split(",")[0]?.trim() : undefined;
  const hostRaw = forwardedHost ?? getHeaderValue(headers, "host");
  const host = typeof hostRaw === "string" && hostRaw.length > 0 ? hostRaw : "localhost";

  const path = raw.startsWith("/") ? raw : `/${raw}`;
  return `${protocol}://${host}${path}`;
}

export function parseVerifyBody(input: unknown): AdapterVerifyBody {
  if (input === null || typeof input !== "object") {
    throw new AgeCheckError(ErrorCode.INVALID_INPUT, "request body must be an object");
  }

  const body = input as Record<string, unknown>;
  const provider = typeof body.provider === "string" && body.provider.length > 0 ? body.provider : undefined;
  const jwt = typeof body.jwt === "string" && body.jwt.length > 0 ? body.jwt : undefined;
  const redirect = typeof body.redirect === "string" ? body.redirect : undefined;

  let payload: AdapterVerifyBody["payload"];
  if (body.payload !== undefined) {
    if (body.payload === null || typeof body.payload !== "object") {
      throw new AgeCheckError(ErrorCode.INVALID_INPUT, "payload must be an object when provided");
    }
    const payloadObj = body.payload as Record<string, unknown>;
    const session =
      typeof payloadObj.agegateway_session === "string" && payloadObj.agegateway_session.length > 0
        ? payloadObj.agegateway_session
        : undefined;
    payload = session === undefined ? {} : { agegateway_session: session };
  }

  const result: AdapterVerifyBody = {};
  if (provider !== undefined) result.provider = provider;
  if (jwt !== undefined) result.jwt = jwt;
  if (payload !== undefined) result.payload = payload;
  if (redirect !== undefined) result.redirect = redirect;
  return result;
}

function failure(status: number, code: string, error: string, detail?: string): VerifyOutcomeFailure {
  const body: VerificationFailureResponse = {
    verified: false,
    code,
    error,
  };

  if (typeof detail === "string" && detail.length > 0) {
    body.detail = detail;
  }

  return {
    ok: false,
    status,
    body,
  };
}

export async function verifyAndBuildOutcome(
  sdk: AgeCheckSdk,
  rawBody: unknown,
  options: AdapterOptions,
): Promise<VerifyOutcome> {
  let body: AdapterVerifyBody;
  try {
    body = parseVerifyBody(rawBody);
  } catch (error: unknown) {
    if (error instanceof AgeCheckError) {
      return failure(400, error.code, "Invalid request payload", error.message);
    }
    return failure(400, ErrorCode.INVALID_INPUT, "Invalid request payload");
  }

  const expectedSession = body.payload?.agegateway_session;
  const redirect = normalizeRedirect(body.redirect);
  const provider = body.provider ?? "agecheck";

  let assertion: VerificationAssertion;
  if (provider === "agecheck") {
    if (typeof body.jwt !== "string") {
      return failure(400, ErrorCode.INVALID_INPUT, "Missing jwt for agecheck provider");
    }

    const verify = await sdk.verifyToken(body.jwt, expectedSession);
    if (!verify.ok) {
      return failure(401, verify.code, "Age validation failed.", verify.detail);
    }

    assertion = {
      provider: "agecheck",
      verified: true,
      level: verify.ageTier,
      verifiedAtUnix: Math.floor(Date.now() / 1000),
      assurance: "passkey",
    };
  } else {
    if (typeof options.providerVerifier !== "function") {
      return failure(400, ErrorCode.INVALID_INPUT, "Unknown provider and no provider verifier configured");
    }

    const providerResult = await options.providerVerifier(body);
    if (!providerResult.verified) {
      return failure(401, providerResult.code, providerResult.message, providerResult.detail);
    }

    if (expectedSession !== undefined && providerResult.session !== expectedSession) {
      return failure(401, ErrorCode.SESSION_BINDING_MISMATCH, "Session binding mismatch.");
    }

    const providerAssertion: VerificationAssertion = {
      provider: providerResult.provider,
      verified: true,
      level: providerResult.level,
      verifiedAtUnix: providerResult.verifiedAtUnix ?? Math.floor(Date.now() / 1000),
    };
    if (providerResult.assurance !== undefined) {
      providerAssertion.assurance = providerResult.assurance;
    }
    assertion = providerAssertion;
  }

  let setCookie: string;
  try {
    setCookie = await sdk.buildSetCookieFromAssertion(assertion);
  } catch (error: unknown) {
    if (error instanceof AgeCheckError) {
      return failure(500, error.code, "Failed to issue verification cookie", error.message);
    }
    return failure(500, ErrorCode.VERIFY_FAILED, "Failed to issue verification cookie");
  }

  return {
    ok: true,
    setCookie,
    body: {
      verified: true,
      redirect,
      ageTier: assertion.level,
    },
  };
}
