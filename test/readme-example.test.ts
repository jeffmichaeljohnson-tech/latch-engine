// A usage example in a README rots the moment the surface moves under it, and a
// broken example reads worse than none. So the exact code from the README's
// "Use" section runs here and its output is pinned. The only difference from the
// README is the import specifier: the README imports from the package name
// "latch-engine", which the "exports" map resolves to this same ./src barrel.
import { describe, it, expect } from "vitest";
import { matchNameservers, planEmailRecords } from "../src/index";

describe("README 'Use' example", () => {
  it("identifies the DNS host from its nameservers", () => {
    const host = matchNameservers([
      "aida.ns.cloudflare.com",
      "rick.ns.cloudflare.com",
    ]);
    expect(host).toMatchObject({
      id: "cloudflare",
      displayName: "Cloudflare",
      treatment: "cloudflare",
    });
  });

  it("plans exactly the two records the README shows, with no warnings", () => {
    const { records, warnings } = planEmailRecords(
      {
        subdomain: "send",
        spfIncludes: ["include:_spf.resend.com"],
        dmarcTags: { p: "none" },
      },
      [],
    );
    expect(warnings).toEqual([]);
    expect(records.map((r) => [r.type, r.host, r.value])).toEqual([
      ["TXT", "send", "v=spf1 include:_spf.resend.com ~all"],
      ["TXT", "_dmarc.send", "v=DMARC1; p=none"],
    ]);
  });
});
