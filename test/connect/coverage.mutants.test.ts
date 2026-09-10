// Latch — coverage policy: mutation-hardening tests.
//
// Companion to coverage.test.ts. That file pins the four known methods; this one
// closes the survivors on isWired()'s tail: the namecheap branch and the default
// `return false`. Each test says WHICH defect it prevents and carries a positive
// negative-control so a function that always returns the same answer still fails.
//
// See the report notes below for the two EQUIVALENT mutants on line 47 that no
// test can distinguish.

import { describe, expect, it } from "vitest";
import { V1_COVERAGE, isWired } from "../../src/connect/coverage";

describe("coverage policy — isWired tail branches", () => {
  it("an UNKNOWN adapter id is not wired — the default return false (L51)", async () => {
    // Prevents the final `return false` becoming `return true`: any adapter id
    // that is neither route53 nor namecheap has no automated path and must be
    // reported unwired.
    expect(isWired("adapter:mystery", V1_COVERAGE)).toBe(false);
    // NEGATIVE CONTROL: a genuinely-wired id must still return true, so the
    // assertion above cannot pass against a function stuck on `false`.
    expect(isWired("adapter:route53", V1_COVERAGE)).toBe(true);
  });

  it("an unknown adapter id stays unwired even when the namecheap flag is ON (L50)", async () => {
    // Prevents the L50 `if (id === "namecheap")` guard being forced true: with
    // that mutation an unknown id would return policy.namecheap. Turning the
    // namecheap flag on and asserting the unknown id is STILL unwired catches it.
    const policy = { ...V1_COVERAGE, namecheap: true };
    expect(isWired("adapter:mystery", policy)).toBe(false);
    // NEGATIVE CONTROL: with the flag on, the real namecheap id IS wired — proves
    // the assertion is not passing simply because everything reads false.
    expect(isWired("adapter:namecheap", policy)).toBe(true);
  });
});
