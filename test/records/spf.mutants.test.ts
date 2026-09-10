// Mutation-closing tests for src/records/spf.ts.
// Each test names the DEFECT it prevents. Where an SPF rule is fixed by RFC 7208
// it is asserted as an external oracle (marked RFC), which is stronger than a pin.
import { describe, expect, it } from "vitest";
import {
  countSpfLookups,
  findSpfRecord,
  mergeSpf,
  parseSpf,
} from "../../src/records/spf";

describe("spf.findSpfRecord — the v=spf1 recogniser is anchored", () => {
  it("does NOT treat a TXT that merely contains v=spf1 mid-string as the SPF record", () => {
    // Prevents dropping the ^ anchor: a verification token that embeds "v=spf1"
    // is not an SPF record (RFC 7208 §3.1 — an SPF record BEGINS with v=spf1).
    expect(findSpfRecord(["notspf-token v=spf1 include:x"])).toBeUndefined();
  });

  it("recognises a bare v=spf1 record with no terms and no trailing space", () => {
    // Prevents dropping the `$` from (\s|$): a record that is exactly "v=spf1"
    // must still be found.
    expect(findSpfRecord(["v=spf1"])).toBe("v=spf1");
  });

  it("finds a record that carries leading whitespace (the source trims before testing)", () => {
    // Prevents dropping .trim(): a padded TXT string must still match.
    expect(findSpfRecord([" v=spf1 include:x ~all"])).toBe(" v=spf1 include:x ~all");
  });
});

describe("spf.parseSpf — token splitting and prefix handling", () => {
  it("drops a leading v=spf1 only after trimming (no phantom v=spf1 term)", () => {
    // Prevents dropping .trim() before split: without it a leading space makes
    // tokens[0] an empty string, so "v=spf1" is not recognised and leaks into terms.
    expect(parseSpf(" v=spf1 include:x -all").terms).toEqual(["include:x"]);
  });

  it("keeps the first term when the record has no v=spf1 prefix", () => {
    // Prevents forcing the slice(1) branch to always run: a prefix-less record
    // must not silently lose its first mechanism.
    expect(parseSpf("include:x ip4:1.2.3.4 -all").terms).toEqual([
      "include:x",
      "ip4:1.2.3.4",
    ]);
  });

  it("an empty record yields no terms and no all (empty tokens are skipped)", () => {
    // Prevents both the `t === ""` guard being disabled and its literal changing:
    // an empty string must never appear as a term.
    expect(parseSpf("").terms).toEqual([]);
    expect(parseSpf("").all).toBeNull();
  });

  it("only the exact all mechanism is the qualifier — a host ending in 'all' is a term", () => {
    // Prevents dropping the ^ from ALL_RE: "include:example.overall" ends in
    // "all" but is a normal term, not the SPF `all` mechanism (RFC 7208 §5.1).
    expect(parseSpf("v=spf1 include:example.overall -all").terms).toEqual([
      "include:example.overall",
    ]);
    expect(parseSpf("v=spf1 include:example.overall -all").all).toBe("-all");
  });

  it("a token that merely starts with 'all' is a term, not the all mechanism", () => {
    // Prevents dropping the `$` from ALL_RE: only the whole token "all" (with an
    // optional qualifier) is the `all` mechanism (RFC 7208 §5.1).
    expect(parseSpf("v=spf1 allmail.example -all").terms).toEqual(["allmail.example"]);
  });

  it("a bare 'all' with no qualifier is still the all mechanism", () => {
    // Prevents making the qualifier mandatory ([-~?+]? -> [-~?+]): a bare `all`
    // is valid and defaults to +all (RFC 7208 §5.1 / §4.6.2).
    expect(parseSpf("v=spf1 include:x all").all).toBe("all");
    expect(parseSpf("v=spf1 include:x all").terms).toEqual(["include:x"]);
  });
});

describe("spf.countSpfLookups — RFC 7208 §4.6.4 lookup accounting", () => {
  it("ip4/ip6 cost zero DNS lookups (negative control)", () => {
    // RFC 7208 §4.6.4: ip4, ip6 and all do NOT count against the 10-lookup limit.
    expect(countSpfLookups(["ip4:1.2.3.4", "ip6:2001:db8::1"])).toBe(0);
  });

  it("a qualified include is still exactly one lookup", () => {
    // Prevents negating the qualifier class in the include/exists regex: a
    // qualifier does not change the lookup cost (RFC 7208 §4.6.4).
    expect(countSpfLookups(["-include:example.com"])).toBe(1);
  });

  it("a token that only embeds 'exists:' mid-string is not an exists mechanism", () => {
    // Prevents dropping the ^ from the include/exists regex: the mechanism name
    // must begin the term (RFC 7208 §5 mechanism grammar).
    expect(countSpfLookups(["xexists:example.com"])).toBe(0);
  });

  it("only a leading redirect= modifier is a lookup", () => {
    // Prevents dropping the ^ from the redirect regex.
    expect(countSpfLookups(["prefix-redirect=example.com"])).toBe(0);
    expect(countSpfLookups(["redirect=example.com"])).toBe(1);
  });

  it("a qualified a/mx/ptr mechanism counts as one lookup", () => {
    // Prevents negating the leading qualifier class in the a/mx/ptr regex.
    expect(countSpfLookups(["-mx"])).toBe(1);
  });

  it("a/mx/ptr followed by ':' or '/' still counts (dual-cidr / domain-spec form)", () => {
    // Prevents negating the ([:/]|$) class: "mx:host" and "a/24" are lookup
    // mechanisms (RFC 7208 §5.3 / §5.4 domain-spec + dual-cidr-length).
    expect(countSpfLookups(["mx:mail.example.com"])).toBe(1);
    expect(countSpfLookups(["a/24"])).toBe(1);
  });

  it("a token whose a/mx/ptr letters are not the leading name is not a lookup", () => {
    // Prevents dropping the ^ from the a/mx/ptr regex: "0mx" is not the mx
    // mechanism (RFC 7208 §5 mechanism grammar requires the name at the start).
    expect(countSpfLookups(["0mx"])).toBe(0);
  });
});

describe("spf.mergeSpf — never a second v=spf1 (RFC 7208 §3.2 permerror)", () => {
  it("an incoming v=spf1 token is dropped, never emitted as a duplicate", () => {
    // Prevents disabling the tokenizer skip (condition/operator/case/literal
    // mutants): two v=spf1 in one record is a permerror and fails ALL mail.
    const { record } = mergeSpf({ additions: ["v=spf1 include:x"] });
    expect(record.match(/v=spf1/gi)?.length).toBe(1);
    expect(record).toBe("v=spf1 include:x ~all");
  });

  it("an empty addition string does not inject an empty term", () => {
    // Prevents changing the `tok === ""` literal: an empty token must be skipped,
    // not folded into the record as a stray space.
    expect(mergeSpf({ additions: [""] }).record).toBe("v=spf1 ~all");
  });

  it("the existing_spf warning quotes the existing (trimmed) record", () => {
    // Prevents blanking the detail template and prevents dropping .trim() on it.
    const { warnings } = mergeSpf({
      existingTxt: [" v=spf1 include:x ~all "],
      additions: ["include:y"],
    });
    const warn = warnings.find((w) => w.code === "existing_spf");
    expect(warn).toBeDefined();
    expect(warn?.detail).toContain("v=spf1 include:x ~all");
    expect(warn?.detail.endsWith("~all")).toBe(true); // trimmed, no trailing space
  });

  it("the spf_lookup_limit warning cites RFC 7208 and the cap", () => {
    // Prevents blanking the lookup-limit detail string.
    const additions = Array.from({ length: 11 }, (_, i) => `include:spf${i}.example.com`);
    const warn = mergeSpf({ additions }).warnings.find((w) => w.code === "spf_lookup_limit");
    expect(warn?.detail).toContain("RFC 7208");
    expect(warn?.detail).toContain("10");
  });
});
