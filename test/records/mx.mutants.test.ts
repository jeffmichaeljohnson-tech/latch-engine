// Mutation-closing tests for src/records/mx.ts.
// MX RDATA is <preference> <exchange> (RFC 1035 §3.3.9); each preference must be
// unique or a resolver chooses nondeterministically. Null-MX is RFC 7505.
import { describe, expect, it } from "vitest";
import { buildMx } from "../../src/records/mx";
import { LatchError } from "../../src/types";

describe("mx.buildMx — warning accumulator starts empty", () => {
  it("emits no warnings when there is no incumbent MX and no duplicate", () => {
    // Prevents seeding the warnings array with a stray element.
    const { warnings } = buildMx({
      entries: [{ priority: 10, target: "aspmx.l.google.com" }],
    });
    expect(warnings).toHaveLength(0);
  });

  it("the existing_mx warning detail is non-empty and names the incumbents", () => {
    // Prevents blanking the existing_mx detail string.
    const { warnings } = buildMx({
      entries: [{ priority: 10, target: "aspmx.l.google.com" }],
      existingMx: ["mx1.incumbent.com"],
    });
    const warn = warnings.find((w) => w.code === "existing_mx");
    expect(warn?.detail).toContain("mx1.incumbent.com");
    expect(warn?.detail).toContain("already receives mail");
  });
});

describe("mx.buildMx — duplicate preference is rejected (RFC 1035 §3.3.9)", () => {
  it("throws provider_rejected naming a unique preference on a duplicate", () => {
    // Prevents blanking the LatchError code and the message string.
    let err: unknown;
    try {
      buildMx({
        entries: [
          { priority: 10, target: "a.example.com" },
          { priority: 10, target: "b.example.com" },
        ],
      });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(LatchError);
    expect((err as LatchError).code).toBe("provider_rejected");
    expect((err as LatchError).message).toContain("unique preference");
  });
});

describe("mx.buildMx — null-MX (RFC 7505)", () => {
  it("emits the single '.' target at the apex with the mx purpose", () => {
    // Prevents blanking the "." value and the "mx" purpose on the null-MX record.
    const { records } = buildMx({
      entries: [{ priority: 10, target: "ignored.example.com" }],
      nullMx: true,
    });
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      type: "MX",
      value: ".",
      priority: 0,
      purpose: "mx",
    });
  });
});
