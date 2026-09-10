// Mutation-closing tests for src/verify/status.ts.
// Focus: the `authoritativeConfirmed === false` branch (L58), which the existing
// suite exercises only with confirmed=0/1 — cases where the branch and the
// external-zone fall-through happen to agree.
import { describe, it, expect } from "vitest";
import { recordStatus, type RecordObservation } from "../../src/verify/status";

const obs = (o: Partial<RecordObservation>): RecordObservation => ({
  confirmed: 0,
  total: 0,
  errors: 0,
  ...o,
});

describe("recordStatus — authoritative-absent branch is distinct from external consensus", () => {
  it("authoritative=false with full public agreement is only 'propagating', never 'confirmed'", () => {
    // Prevents emptying the `authoritativeConfirmed === false` block, forcing its
    // condition false, or flipping its literal to true. In every one of those the
    // record would fall through to the external path and report the strong
    // "confirmed" terminal — but the authoritative source says the record is NOT
    // there yet, so a public resolver seeing it is movement, not success.
    expect(
      recordStatus(obs({ authoritativeConfirmed: false, confirmed: 2, total: 2 })),
    ).toBe("propagating");
  });

  it("authoritative=false with no public confirmation stays 'pending'", () => {
    // The other half of the same branch, so the branch cannot be a no-op that
    // still passes the case above by accident.
    expect(
      recordStatus(obs({ authoritativeConfirmed: false, confirmed: 0, total: 2 })),
    ).toBe("pending");
  });
});
