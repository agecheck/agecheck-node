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

import { AgeCheckError, ErrorCode, type AgeCheckSdk, type VerificationAssertion as CoreVerificationAssertion } from "@agecheck/core";

export interface ProviderAssertion {
  provider: string;
  verified: true;
  level: string;
  session: string;
  verifiedAtUnix: number;
  assurance?: string;
  verificationType?: "passkey" | "oid4vp" | "other";
  evidenceType?: "webauthn_assertion" | "sd_jwt" | "zk_attestation" | "other";
  providerTransactionId?: string;
  loa?: string;
}

export interface ExternalProviderAssertion {
  provider: string;
  verified: true;
  level: string;
  session: string;
  verifiedAtUnix?: number;
  assurance?: string;
  verificationType?: "passkey" | "oid4vp" | "other";
  evidenceType?: "webauthn_assertion" | "sd_jwt" | "zk_attestation" | "other";
  providerTransactionId?: string;
  loa?: string;
}

export interface ProviderFailure {
  verified: false;
  code: string;
  message: string;
  detail?: string;
}

export type ProviderVerificationResult = ExternalProviderAssertion | ProviderFailure;
export type NormalizedProviderVerificationResult = ProviderAssertion | ProviderFailure;

export interface VerifyAgeCheckCredentialInput {
  jwt: string;
  expectedSession: string;
  provider?: string;
  assurance?: string;
  verificationType?: "passkey" | "oid4vp" | "other";
  evidenceType?: "webauthn_assertion" | "sd_jwt" | "zk_attestation" | "other";
  providerTransactionId?: string;
  loa?: string;
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function isSessionIdentifier(value: string): boolean {
  return UUID_PATTERN.test(value);
}

function isAgeTier(value: string): boolean {
  return /^[1-9]\d*\+$/.test(value);
}

function isVerificationType(value: string): value is "passkey" | "oid4vp" | "other" {
  return value === "passkey" || value === "oid4vp" || value === "other";
}

function isEvidenceType(value: string): value is "webauthn_assertion" | "sd_jwt" | "zk_attestation" | "other" {
  return value === "webauthn_assertion" || value === "sd_jwt" || value === "zk_attestation" || value === "other";
}

function normalizeProviderName(provider: string | undefined): string | null {
  if (typeof provider !== "string") {
    return "agecheck";
  }
  const trimmed = provider.trim();
  if (trimmed.length === 0) {
    return null;
  }
  return trimmed;
}

function fail(code: string, message: string, detail?: string): ProviderFailure {
  const out: ProviderFailure = {
    verified: false,
    code,
    message,
  };
  if (typeof detail === "string" && detail.length > 0) {
    out.detail = detail;
  }
  return out;
}

export async function verifyAgeCheckCredential(
  sdk: AgeCheckSdk,
  input: VerifyAgeCheckCredentialInput,
): Promise<NormalizedProviderVerificationResult> {
  if (typeof input.jwt !== "string" || input.jwt.length === 0) {
    return fail(ErrorCode.INVALID_INPUT, "Missing jwt for agecheck provider.");
  }

  if (typeof input.expectedSession !== "string" || input.expectedSession.length === 0) {
    return fail(ErrorCode.INVALID_INPUT, "expectedSession must be a non-empty string.");
  }
  if (!isSessionIdentifier(input.expectedSession)) {
    return fail(ErrorCode.INVALID_INPUT, "expectedSession must be a UUID.");
  }

  const provider = normalizeProviderName(input.provider);
  if (provider === null) {
    return fail(ErrorCode.INVALID_INPUT, "provider must be a non-empty string.");
  }

  const verify = await sdk.verifyToken(input.jwt, input.expectedSession);
  if (!verify.ok) {
    return fail(verify.code, "Age validation failed.", verify.detail);
  }

  const verificationType = input.verificationType ?? "passkey";
  if (!isVerificationType(verificationType)) {
    return fail(ErrorCode.INVALID_INPUT, "verificationType is invalid.");
  }

  const evidenceType = input.evidenceType ?? "webauthn_assertion";
  if (!isEvidenceType(evidenceType)) {
    return fail(ErrorCode.INVALID_INPUT, "evidenceType is invalid.");
  }

  const claims = verify.claims;
  const transactionClaim = claims.jti;
  const transactionId =
    typeof input.providerTransactionId === "string" && input.providerTransactionId.length > 0
      ? input.providerTransactionId
      : typeof transactionClaim === "string" && transactionClaim.length > 0
        ? transactionClaim
        : undefined;

  let loa: string | undefined;
  if (typeof input.loa === "string" && input.loa.length > 0) {
    loa = input.loa;
  } else {
    const vc = claims.vc;
    if (vc && typeof vc === "object") {
      const credentialSubject = (vc as { credentialSubject?: unknown }).credentialSubject;
      if (credentialSubject && typeof credentialSubject === "object") {
        const loaCandidate = (credentialSubject as { loa?: unknown }).loa;
        if (typeof loaCandidate === "string" && loaCandidate.length > 0) {
          loa = loaCandidate;
        }
      }
    }
  }

  const now = Math.floor(Date.now() / 1000);
  const assertion: ProviderAssertion = {
    provider,
    verified: true,
    level: verify.ageTier,
    session: input.expectedSession,
    verifiedAtUnix: now,
    verificationType,
    evidenceType,
  };
  if (typeof input.assurance === "string" && input.assurance.length > 0) {
    assertion.assurance = input.assurance;
  }
  if (typeof transactionId === "string" && transactionId.length > 0) {
    assertion.providerTransactionId = transactionId;
  }
  if (typeof loa === "string" && loa.length > 0) {
    assertion.loa = loa;
  }
  return assertion;
}

export function normalizeExternalProviderAssertion(
  providerResult: ProviderVerificationResult,
  expectedSession: string | undefined,
): NormalizedProviderVerificationResult {
  if (expectedSession !== undefined && !isSessionIdentifier(expectedSession)) {
    return fail(ErrorCode.INVALID_INPUT, "expected session must be a UUID.");
  }

  if (!providerResult.verified) {
    return providerResult;
  }

  if (typeof providerResult.provider !== "string" || providerResult.provider.trim().length === 0) {
    return fail(ErrorCode.INVALID_INPUT, "provider must be a non-empty string.");
  }

  if (typeof providerResult.level !== "string" || !isAgeTier(providerResult.level)) {
    return fail(ErrorCode.INVALID_INPUT, "provider level must be an age tier like 18+.");
  }

  if (typeof providerResult.session !== "string" || providerResult.session.length === 0) {
    return fail(ErrorCode.SESSION_BINDING_REQUIRED, "Provider session is required.");
  }
  if (!isSessionIdentifier(providerResult.session)) {
    return fail(ErrorCode.INVALID_INPUT, "Provider session must be a UUID.");
  }

  if (expectedSession !== undefined && providerResult.session !== expectedSession) {
    return fail(ErrorCode.SESSION_BINDING_MISMATCH, "Session binding mismatch.");
  }

  const verifiedAtUnixRaw = providerResult.verifiedAtUnix;
  const verifiedAtUnix =
    Number.isInteger(verifiedAtUnixRaw) && typeof verifiedAtUnixRaw === "number" && verifiedAtUnixRaw > 0
      ? verifiedAtUnixRaw
      : Math.floor(Date.now() / 1000);

  const normalized: ProviderAssertion = {
    provider: providerResult.provider.trim(),
    verified: true,
    level: providerResult.level,
    session: providerResult.session,
    verifiedAtUnix,
  };

  if (typeof providerResult.verificationType === "string") {
    if (!isVerificationType(providerResult.verificationType)) {
      return fail(ErrorCode.INVALID_INPUT, "verificationType is invalid.");
    }
    normalized.verificationType = providerResult.verificationType;
  }
  if (typeof providerResult.evidenceType === "string") {
    if (!isEvidenceType(providerResult.evidenceType)) {
      return fail(ErrorCode.INVALID_INPUT, "evidenceType is invalid.");
    }
    normalized.evidenceType = providerResult.evidenceType;
  }
  if (typeof providerResult.providerTransactionId === "string" && providerResult.providerTransactionId.length > 0) {
    normalized.providerTransactionId = providerResult.providerTransactionId;
  }
  if (typeof providerResult.loa === "string" && providerResult.loa.length > 0) {
    normalized.loa = providerResult.loa;
  }
  if (typeof providerResult.assurance === "string" && providerResult.assurance.length > 0) {
    normalized.assurance = providerResult.assurance;
  }
  return normalized;
}

export function toCoreVerificationAssertion(assertion: ProviderAssertion): CoreVerificationAssertion {
  const coreAssertion: CoreVerificationAssertion = {
    provider: assertion.provider,
    verified: true,
    level: assertion.level,
    verifiedAtUnix: assertion.verifiedAtUnix,
  };
  if (typeof assertion.assurance === "string" && assertion.assurance.length > 0) {
    coreAssertion.assurance = assertion.assurance;
  }
  return coreAssertion;
}

export async function buildSetCookieFromProviderAssertion(
  sdk: AgeCheckSdk,
  assertion: ProviderAssertion,
): Promise<string> {
  try {
    return await sdk.buildSetCookieFromAssertion(toCoreVerificationAssertion(assertion));
  } catch (error: unknown) {
    if (error instanceof AgeCheckError) {
      throw error;
    }
    throw new AgeCheckError(ErrorCode.VERIFY_FAILED, "Failed to issue verification cookie.");
  }
}
