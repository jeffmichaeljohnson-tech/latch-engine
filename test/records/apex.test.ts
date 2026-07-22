import { describe, expect, it } from "vitest";
import { assertNoApexCname, isApexHost, planApex } from "../../src/records/apex";
import { LatchError } from "../../src/types";
import type { DnsRecord } from "../../src/types";

describe("apex: refuse a literal CNAME at the apex", () => {
  it("throws for a CNAME at @", () => {
    const rec: DnsRecord = { type: "CNAME", host: "@", value: "target.example.com", ttl: 300 };
    expect(() => assertNoApexCname(rec)).toThrow(LatchError);
  });

  it("throws for a CNAME whose host equals the registrable domain", () => {
    const rec: DnsRecord = { type: "CNAME", host: "example.com", value: "t.example.com", ttl: 300 };
    expect(() => assertNoApexCname(rec, "example.com")).toThrow(LatchError);
  });

  it("allows a CNAME on a subdomain", () => {
    const rec: DnsRecord = { type: "CNAME", host: "www", value: "t.example.com", ttl: 300 };
    expect(() => assertNoApexCname(rec, "example.com")).not.toThrow();
  });

  it("isApexHost recognizes @, empty, and the bare domain", () => {
    expect(isApexHost("@")).toBe(true);
    expect(isApexHost("")).toBe(true);
    expect(isApexHost("example.com.", "example.com")).toBe(true);
    expect(isApexHost("www", "example.com")).toBe(false);
  });
});

describe("apex: ALIAS/flatten vs A/AAAA decision", () => {
  it("uses ALIAS when the host supports apex flattening", () => {
    const plan = planApex({ supportsApex: true, target: "app.pages.dev" });
    expect(plan.strategy).toBe("alias");
    if (plan.strategy === "alias") {
      expect(plan.record.type).toBe("ALIAS");
      expect(plan.record.host).toBe("@");
      expect(plan.record.value).toBe("app.pages.dev.");
    }
  });

  it("flattens to A/AAAA when the host lacks apex support but IPs are provided", () => {
    const plan = planApex({
      supportsApex: false,
      target: "app.example.com",
      resolved: { a: ["1.2.3.4"], aaaa: ["2606:4700::1"] },
    });
    expect(plan.strategy).toBe("flatten");
    if (plan.strategy === "flatten") {
      expect(plan.records.map((r) => r.type)).toEqual(["A", "AAAA"]);
      expect(plan.records[0]?.value).toBe("1.2.3.4");
      expect(plan.records[1]?.value).toBe("2606:4700::1");
    }
  });

  it("reports unresolved when there is no apex support and no IPs to flatten", () => {
    const plan = planApex({ supportsApex: false, target: "app.example.com" });
    expect(plan.strategy).toBe("unresolved");
  });
});
