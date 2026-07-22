import { describe, expect, it } from "vitest";
import { V1_COVERAGE, adapterIdOf, isWired } from "../../src/connect/coverage";

describe("coverage policy", () => {
  it("wires Cloudflare + Route53 in v1; Domain Connect, Namecheap, and manual are not", () => {
    expect(isWired("cloudflare", V1_COVERAGE)).toBe(true);
    expect(isWired("adapter:route53", V1_COVERAGE)).toBe(true);
    // Domain Connect is off until the gbuild-email template is authored + registered.
    expect(isWired("domain_connect", V1_COVERAGE)).toBe(false);
    expect(isWired("adapter:namecheap", V1_COVERAGE)).toBe(false);
    expect(isWired("manual", V1_COVERAGE)).toBe(false);
  });

  it("Domain Connect re-wires with a one-flag flip once its template is live", () => {
    expect(isWired("domain_connect", { ...V1_COVERAGE, domainConnect: true })).toBe(true);
  });

  it("extracts the adapter id from an adapter:<id> method", () => {
    expect(adapterIdOf("adapter:route53")).toBe("route53");
    expect(adapterIdOf("cloudflare")).toBeNull();
    expect(adapterIdOf("manual")).toBeNull();
  });

  it("flipping the Namecheap flag re-wires it with no other change", () => {
    expect(isWired("adapter:namecheap", { ...V1_COVERAGE, namecheap: true })).toBe(true);
  });
});
