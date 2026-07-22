import { describe, expect, it } from "vitest";
import {
  countSpfLookups,
  findSpfRecord,
  mergeSpf,
  parseSpf,
} from "../../src/records/spf";

describe("spf: permerror avoidance (never a second v=spf1)", () => {
  it("merges into the single existing record — output has exactly one v=spf1", () => {
    const { record, warnings } = mergeSpf({
      existingTxt: ["v=spf1 include:_spf.google.com ~all"],
      additions: ["include:sendgrid.net"],
    });
    expect(record.match(/v=spf1/gi)?.length).toBe(1);
    expect(record).toBe("v=spf1 include:_spf.google.com include:sendgrid.net ~all");
    expect(warnings.map((w) => w.code)).toContain("existing_spf");
  });

  it("finds the v=spf1 record among unrelated apex TXT verification tokens", () => {
    const txts = [
      "google-site-verification=abc123",
      "MS=ms12345",
      "v=spf1 include:zoho.com -all",
    ];
    expect(findSpfRecord(txts)).toBe("v=spf1 include:zoho.com -all");
  });
});

describe("spf: all-qualifier preservation", () => {
  it("keeps ~all even when the addition carries -all", () => {
    const { record } = mergeSpf({
      existingTxt: ["v=spf1 include:_spf.google.com ~all"],
      additions: ["v=spf1 include:sendgrid.net -all"],
    });
    expect(record.endsWith("~all")).toBe(true);
    expect(record).not.toContain("-all");
  });

  it("defaults to ~all (softfail) on a brand-new record", () => {
    const { record, warnings } = mergeSpf({ additions: ["include:_spf.google.com"] });
    expect(record).toBe("v=spf1 include:_spf.google.com ~all");
    expect(warnings.map((w) => w.code)).not.toContain("existing_spf");
  });

  it("adopts an incoming all only when none exists", () => {
    const { record } = mergeSpf({ additions: ["include:_spf.google.com", "-all"] });
    expect(record).toBe("v=spf1 include:_spf.google.com -all");
  });
});

describe("spf: include dedupe", () => {
  it("does not add a mechanism already present (case-insensitive)", () => {
    const { record } = mergeSpf({
      existingTxt: ["v=spf1 include:_spf.google.com ~all"],
      additions: ["include:_SPF.Google.com", "include:sendgrid.net"],
    });
    expect(record.match(/include:_spf\.google\.com/gi)?.length).toBe(1);
    expect(record).toContain("include:sendgrid.net");
  });
});

describe("spf: 10-lookup limit", () => {
  it("counts DNS-querying terms and ignores ip4/ip6/all", () => {
    const terms = ["include:a.com", "a", "mx", "ptr", "exists:%{i}.x.com", "ip4:1.2.3.4", "ip6:::1"];
    expect(countSpfLookups(terms)).toBe(5);
  });

  it("flags spf_lookup_limit when the merged record exceeds 10 lookups", () => {
    const additions = Array.from({ length: 11 }, (_, i) => `include:spf${i}.example.com`);
    const { lookupCount, warnings } = mergeSpf({ additions });
    expect(lookupCount).toBe(11);
    expect(warnings.map((w) => w.code)).toContain("spf_lookup_limit");
  });

  it("does not flag at exactly 10 lookups", () => {
    const additions = Array.from({ length: 10 }, (_, i) => `include:spf${i}.example.com`);
    const { lookupCount, warnings } = mergeSpf({ additions });
    expect(lookupCount).toBe(10);
    expect(warnings.map((w) => w.code)).not.toContain("spf_lookup_limit");
  });

  it("counts redirect= as a lookup", () => {
    expect(countSpfLookups(["redirect=_spf.example.com"])).toBe(1);
  });
});

describe("spf: parsing", () => {
  it("separates terms from the all qualifier", () => {
    const parsed = parseSpf("v=spf1 include:x.com ip4:1.2.3.4 -all");
    expect(parsed.terms).toEqual(["include:x.com", "ip4:1.2.3.4"]);
    expect(parsed.all).toBe("-all");
  });

  it("emits a canonical apex TXT DnsRecord with a clamped ttl", () => {
    const { dnsRecord } = mergeSpf({ additions: ["include:x.com"], ttl: 60 });
    expect(dnsRecord.type).toBe("TXT");
    expect(dnsRecord.host).toBe("@");
    expect(dnsRecord.purpose).toBe("spf");
    expect(dnsRecord.ttl).toBe(300);
  });
});
