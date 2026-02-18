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
import { AgeCheckSdk } from "../src/index.js";

describe("@agecheck/node", () => {
  it("re-exports AgeCheckSdk", () => {
    expect(typeof AgeCheckSdk).toBe("function");
  });
});
