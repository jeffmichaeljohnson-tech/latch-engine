// Mutation-closing tests for src/records/apex.ts.
// A literal CNAME at the apex is forbidden by RFC 1034 §3.6.2 (it cannot coexist
// with the SOA/NS records every apex carries). Each test names the defect it prevents.
import { describe, expect, it } from "vitest";
import { assertNoApexCname, isApexHost, planApex } from "../../src/records/apex";
import { LatchError } from "../../src/types";
import type { DnsRecord } from "../../src/types";

describe("apex.isApexHost — apex detection", () => {
  it("a subdomain is NOT the apex even when an apex is supplied", () => {
    // Prevents forcing the `apex !== undefined` branch true (which would treat any
    // host as the apex when an apex arg is present).
    expect(isApexHost("www", "example.com")).toBe(false);
  });

  it("matches the bare registrable domain against the supplied apex (trim + case + dot)", () => {
    // Prevents dropping .trim()/.replace()/.toLowerCase() normalisation on either side.
    expect(isApexHost("EXAMPLE.COM.", " example.com ")).toBe(true);
  });

  it("returns false for a non-apex host when no apex arg is given", () => {
    // Prevents the NoCoverage `return false` -> `return true` at the tail.
    expect(isApexHost("mail.example.com")).toBe(false);
  });
});

describe("apex.assertNoApexCname — RFC 1034 apex-CNAME refusal", () => {
  it("does not throw for a CNAME on a subdomain", () => {
    // Prevents forcing the type+apex condition always true.
    const rec: DnsRecord = { type: "CNAME", host: "www", value: "t.example.com", ttl: 300 };
    expect(() => assertNoApexCname(rec, "example.com")).not.toThrow();
  });

  it("throwing at the apex uses code 'unsupported' and cites RFC 1034", () => {
    // Prevents blanking the LatchError code and the message string.
    const rec: DnsRecord = { type: "CNAME", host: "@", value: "t.example.com", ttl: 300 };
    let err: unknown;
    try {
      assertNoApexCname(rec);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(LatchError);
    expect((err as LatchError).code).toBe("unsupported");
    expect((err as LatchError).message).toContain("RFC 1034");
  });
});

describe("apex.planApex — ALIAS / flatten / unresolved decision", () => {
  it("reports unresolved (with a reason) only when there is neither ALIAS support nor IPs", () => {
    // Prevents forcing the `a.length === 0 && aaaa.length === 0` guard true, and
    // prevents blanking the reason string.
    const plan = planApex({ supportsApex: false, target: "app.example.com" });
    expect(plan.strategy).toBe("unresolved");
    if (plan.strategy === "unresolved") {
      expect(plan.reason.length).toBeGreaterThan(0);
      expect(plan.reason).toContain("app.example.com");
    }
  });

  it("flattens to A/AAAA records at the apex host with the site purpose", () => {
    // Prevents blanking the value, host ("@") and purpose ("site") string literals
    // in both the A and AAAA flatten maps.
    const plan = planApex({
      supportsApex: false,
      target: "app.example.com",
      resolved: { a: ["1.2.3.4"], aaaa: ["2606:4700::1"] },
    });
    expect(plan.strategy).toBe("flatten");
    if (plan.strategy === "flatten") {
      expect(plan.records[0]).toMatchObject({
        type: "A",
        host: "@",
        value: "1.2.3.4",
        purpose: "site",
      });
      expect(plan.records[1]).toMatchObject({
        type: "AAAA",
        host: "@",
        value: "2606:4700::1",
        purpose: "site",
      });
    }
  });
});
