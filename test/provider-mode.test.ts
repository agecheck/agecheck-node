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
import type { AgeCheckSdk, VerifyResult } from "@agecheck/core";
import {
  buildSetCookieFromProviderAssertion,
  normalizeExternalProviderAssertion,
  toCoreVerificationAssertion,
  verifyAgeCheckCredential,
  type ProviderAssertion,
} from "../src/index.js";

interface MockSdkOptions {
  verifyResult: VerifyResult;
  setCookieValue?: string;
}

function makeMockSdk(options: MockSdkOptions): AgeCheckSdk {
  const setCookieValue = options.setCookieValue ?? "agecheck_verified=abc";
  return {
    verifyToken: async () => options.verifyResult,
    buildSetCookieFromAssertion: async () => setCookieValue,
  } as unknown as AgeCheckSdk;
}

describe("provider mode helpers", () => {
  it("maps successful AgeCheck verification to provider assertion", async () => {
    const sdk = makeMockSdk({
      verifyResult: {
        ok: true,
        claims: {},
        ageTier: "18+",
        ageTierValue: 18,
      },
    });

    const result = await verifyAgeCheckCredential(sdk, {
      jwt: "jwt",
      expectedSession: "123e4567-e89b-42d3-a456-426614174000",
    });

    expect(result.verified).toBe(true);
    if (result.verified) {
      expect(result.provider).toBe("agecheck");
      expect(result.level).toBe("18+");
      expect(result.session).toBe("123e4567-e89b-42d3-a456-426614174000");
      expect(result.verifiedAtUnix).toBeTypeOf("number");
      expect(result.verificationType).toBe("passkey");
      expect(result.evidenceType).toBe("webauthn_assertion");
    }
  });

  it("returns typed failure when AgeCheck verification fails", async () => {
    const sdk = makeMockSdk({
      verifyResult: {
        ok: false,
        code: "invalid_signature",
        message: "Invalid token signature.",
      },
    });

    const result = await verifyAgeCheckCredential(sdk, {
      jwt: "jwt",
      expectedSession: "123e4567-e89b-42d3-a456-426614174001",
    });

    expect(result).toEqual({
      verified: false,
      code: "invalid_signature",
      message: "Age validation failed.",
    });
  });

  it("rejects non-UUID expected session", async () => {
    const sdk = makeMockSdk({
      verifyResult: {
        ok: true,
        claims: {},
        ageTier: "18+",
        ageTierValue: 18,
      },
    });

    const result = await verifyAgeCheckCredential(sdk, {
      jwt: "jwt",
      expectedSession: "not-a-uuid",
    });

    expect(result).toEqual({
      verified: false,
      code: "invalid_input",
      message: "expectedSession must be a UUID.",
    });
  });

  it("normalizes external provider success and enforces session match", () => {
    const normalized = normalizeExternalProviderAssertion(
      {
        verified: true,
        provider: "yoti-like",
        level: "21+",
        session: "123e4567-e89b-42d3-a456-426614174010",
        verifiedAtUnix: 1,
        verificationType: "oid4vp",
        evidenceType: "sd_jwt",
        providerTransactionId: "txn-1",
        loa: "LOA2",
      },
      "123e4567-e89b-42d3-a456-426614174010",
    );

    expect(normalized.verified).toBe(true);
    if (normalized.verified) {
      expect(normalized.provider).toBe("yoti-like");
      expect(normalized.level).toBe("21+");
      expect(normalized.verificationType).toBe("oid4vp");
      expect(normalized.evidenceType).toBe("sd_jwt");
      expect(normalized.providerTransactionId).toBe("txn-1");
      expect(normalized.loa).toBe("LOA2");
    }

    const mismatch = normalizeExternalProviderAssertion(
      {
        verified: true,
        provider: "other",
        level: "21+",
        session: "123e4567-e89b-42d3-a456-426614174011",
        verifiedAtUnix: 1,
      },
      "123e4567-e89b-42d3-a456-426614174012",
    );

    expect(mismatch.verified).toBe(false);
    if (!mismatch.verified) {
      expect(mismatch.code).toBe("session_binding_mismatch");
    }
  });

  it("converts provider assertion to core assertion and builds set-cookie", async () => {
    const sdk = makeMockSdk({
      verifyResult: {
        ok: true,
        claims: {},
        ageTier: "18+",
        ageTierValue: 18,
      },
      setCookieValue: "agecheck_verified=xyz",
    });

    const assertion: ProviderAssertion = {
      provider: "agecheck",
      verified: true,
      level: "18+",
      session: "123e4567-e89b-42d3-a456-426614174013",
      verifiedAtUnix: 1000,
      assurance: "passkey",
      verificationType: "passkey",
      evidenceType: "webauthn_assertion",
      providerTransactionId: "txn-2",
      loa: "LOA3",
    };

    const coreAssertion = toCoreVerificationAssertion(assertion);
    expect(coreAssertion).toEqual({
      provider: "agecheck",
      verified: true,
      level: "18+",
      verifiedAtUnix: 1000,
      assurance: "passkey",
      verificationType: "passkey",
      evidenceType: "webauthn_assertion",
      providerTransactionId: "txn-2",
      loa: "LOA3",
    });

    const setCookie = await buildSetCookieFromProviderAssertion(sdk, assertion);
    expect(setCookie).toBe("agecheck_verified=xyz");
  });
});
