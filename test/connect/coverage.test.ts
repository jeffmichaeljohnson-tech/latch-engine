import { describe, expect, it } from "vitest";
import { V1_COVERAGE, adapterIdOf, isWired } from "../../src/connect/coverage";

describe("coverage policy", () => {
  it("wires Cloudflare, Domain Connect, and Route53 in v1; Namecheap and manual are not", () => {
    expect(isWired("cloudflare", V1_COVERAGE)).toBe(true);
    expect(isWired("domain_connect", V1_COVERAGE)).toBe(true);
    expect(isWired("adapter:route53", V1_COVERAGE)).toBe(true);
    expect(isWired("adapter:namecheap", V1_COVERAGE)).toBe(false);
    expect(isWired("manual", V1_COVERAGE)).toBe(false);
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
