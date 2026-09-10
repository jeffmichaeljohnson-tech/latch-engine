import { describe, expect, it } from "vitest";
import {
  clampTtl,
  deriveVars,
  EMAIL_PROVIDER_SPF,
  emailProviderSpfInclude,
  MULTI_PART_SUFFIXES,
  MIN_TTL,
  normalizeFqdn,
  resolveVarsAll,
  splitSldTld,
} from "../../src/records/vars";
import type { DnsRecord, RecordVars } from "../../src/types";

// Mutation-closing tests for src/records/vars.ts.
//
// The existing test/records/vars.test.ts covers the happy path (one provider
// alias, one multi-part suffix, one plain split). This file pins the parts a
// mutation run left open: the WHOLE provider alias table, the WHOLE multi-part
// suffix set, the SLD/TLD split against real-world hostname shapes (a single
// label, an empty string, a trailing root dot, a leading dot, a bare suffix),
// clampTtl's boundary, normalizeFqdn's trim, resolveVarsAll (uncovered), and
// deriveVars called with no options (uncovered).
//
// Fixtures are real registrable domains wherever the pairing is a fact about the
// world (bbc.co.uk, telstra.com.au, sony.co.jp). Where the second-level label is
// only illustrative it is marked so — but in every row the SUFFIX under test is a
// real public-suffix rule, which is the thing the assertion actually pins.

// ---------------------------------------------------------------------------
// email provider -> SPF include token
// ---------------------------------------------------------------------------

describe("emailProviderSpfInclude: full alias table", () => {
  // Each row pins one map value. Prevents blanking any value to "" (the survived
  // StringLiteral mutants on every EMAIL_PROVIDER_SPF entry): an alias that
  // resolved to "" would silently drop the sending provider from the SPF record.
  const ALIASES: ReadonlyArray<readonly [alias: string, include: string]> = [
    ["google", "include:_spf.google.com"],
    ["google-workspace", "include:_spf.google.com"],
    ["googleworkspace", "include:_spf.google.com"],
    ["gsuite", "include:_spf.google.com"],
    ["gmail", "include:_spf.google.com"],
    ["microsoft", "include:spf.protection.outlook.com"],
    ["microsoft365", "include:spf.protection.outlook.com"],
    ["365", "include:spf.protection.outlook.com"],
    ["o365", "include:spf.protection.outlook.com"],
    ["office365", "include:spf.protection.outlook.com"],
    ["outlook", "include:spf.protection.outlook.com"],
    ["zoho", "include:zoho.com"],
    ["sendgrid", "include:sendgrid.net"],
    ["mailgun", "include:mailgun.org"],
    ["amazonses", "include:amazonses.com"],
    ["ses", "include:amazonses.com"],
    ["mailchimp", "include:servers.mcsv.net"],
    ["mandrill", "include:spf.mandrillapp.com"],
    ["postmark", "include:spf.mtasv.net"],
    ["resend", "include:_spf.resend.com"],
  ];

  it.each(ALIASES)("%s -> its exact include token", (alias, include) => {
    expect(emailProviderSpfInclude(alias)).toBe(include);
  });

  it("covers every key in EMAIL_PROVIDER_SPF (completeness control)", () => {
    // Control, in the spirit of ns-map.entries.test.ts. The per-alias rows above
    // only prove what the table names; a map that quietly gained or lost a key
    // would still pass them all. This fails when the two sets diverge, so a new
    // provider added without a fixture is caught here rather than sitting untested.
    const fixtureKeys = new Set(ALIASES.map(([a]) => a));
    const mapKeys = new Set(Object.keys(EMAIL_PROVIDER_SPF));
    expect(fixtureKeys).toEqual(mapKeys);
    expect(mapKeys.size).toBe(20);
  });

  it("trims and lower-cases the provider before lookup", () => {
    // Prevents dropping .trim().toLowerCase() (the L44 MethodExpression mutant):
    // without it, real-world input with stray case or padding would miss the map.
    expect(emailProviderSpfInclude("  GOOGLE-Workspace ")).toBe("include:_spf.google.com");
    expect(emailProviderSpfInclude("SENDGRID")).toBe("include:sendgrid.net");
  });

  it("returns undefined for an unknown provider (negative control)", () => {
    expect(emailProviderSpfInclude("carrier-pigeon")).toBeUndefined();
    expect(emailProviderSpfInclude("")).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// SLD / TLD split — real-world hostname shapes
// ---------------------------------------------------------------------------

describe("splitSldTld: normalization of the input host", () => {
  it("lower-cases before splitting (real host in shouting case)", () => {
    // Prevents dropping the canon() chain entirely (L98 MethodExpression):
    // BBC.CO.UK must split to the same lowercase labels as bbc.co.uk.
    expect(splitSldTld("BBC.CO.UK")).toEqual({ sld: "bbc", tld: "co.uk" });
  });

  it("strips a single trailing root dot (an FQDN as it arrives on the wire)", () => {
    // Prevents mutating the replace(/\.$/, "") target to a sentinel string
    // (L98 StringLiteral): a trailing "." would otherwise fuse into the tld.
    expect(splitSldTld("example.com.")).toEqual({ sld: "example", tld: "com" });
  });
});

describe("splitSldTld: degenerate label counts", () => {
  it("returns empty sld/tld for the empty string", () => {
    // Covers + pins the length===0 branch (L107 ObjectLiteral + StringLiterals):
    // an empty host must yield empty parts, not "{}" and not a sentinel.
    expect(splitSldTld("")).toEqual({ sld: "", tld: "" });
  });

  it("treats a lone root dot as empty (canon strips it to nothing)", () => {
    expect(splitSldTld(".")).toEqual({ sld: "", tld: "" });
  });

  it("keeps a single label as the sld with an empty tld", () => {
    // Pins the length===1 branch (L108 conditional/ObjectLiteral/LogicalOperator
    // and the tld "" literal): "localhost" is sld=localhost, NOT sld="" tld=localhost.
    expect(splitSldTld("localhost")).toEqual({ sld: "localhost", tld: "" });
  });
});

describe("splitSldTld: the multi-part-suffix branch guard", () => {
  it("does NOT enter the multi-part branch for a bare two-label suffix", () => {
    // Prevents forcing `labels.length >= 3` to true (L110): with the guard forced
    // on, the bare suffix "co.uk" would be read as tld=co.uk with an empty sld.
    // The real code, seeing only two labels, splits it as an ordinary sld/tld.
    expect(splitSldTld("co.uk")).toEqual({ sld: "co", tld: "uk" });
  });

  it("drops an empty leading label before the branch is chosen", () => {
    // Prevents dropping the `.filter(l => l.length > 0)` (L106 MethodExpression /
    // ConditionalExpression / EqualityOperator). WITHOUT the filter, ".co.uk"
    // keeps its empty first label, becomes three labels, matches the co.uk suffix
    // rule, and mis-splits to { sld:"", tld:"co.uk" }. WITH the filter it degrades
    // to the two-label split below. This pins the real (filtered) behavior.
    expect(splitSldTld(".co.uk")).toEqual({ sld: "co", tld: "uk" });
  });

  it("takes the registrable label under a deep subdomain on a multi-part suffix", () => {
    // Exercises the labels.length-3 index path (L113 branch).
    expect(splitSldTld("www.bbc.co.uk")).toEqual({ sld: "bbc", tld: "co.uk" });
  });
});

describe("splitSldTld: every multi-part suffix in the set", () => {
  // One 3-label domain per suffix. Prevents blanking any suffix to "" (the
  // survived StringLiteral mutants across MULTI_PART_SUFFIXES): a blanked suffix
  // is no longer recognized, so a domain under it mis-splits (e.g. bbc.co.uk ->
  // sld=co/tld=uk instead of sld=bbc/tld=co.uk). Real provider pairings are noted;
  // an "illustrative" label still pins the real suffix rule beside it.
  const SUFFIX_FIXTURES: ReadonlyArray<readonly [domain: string, sld: string, tld: string]> = [
    // United Kingdom
    ["bbc.co.uk", "bbc", "co.uk"], // BBC — real
    ["nationaltrust.org.uk", "nationaltrust", "org.uk"], // National Trust — real
    ["example.me.uk", "example", "me.uk"], // illustrative label, real .me.uk suffix
    ["example.ltd.uk", "example", "ltd.uk"], // illustrative
    ["example.plc.uk", "example", "plc.uk"], // illustrative
    ["example.net.uk", "example", "net.uk"], // illustrative
    ["stmarys.sch.uk", "stmarys", "sch.uk"], // .sch.uk is the real UK schools suffix
    ["ox.ac.uk", "ox", "ac.uk"], // University of Oxford — real
    ["hmrc.gov.uk", "hmrc", "gov.uk"], // HMRC — real GOV.UK domain
    // Australia
    ["telstra.com.au", "telstra", "com.au"], // Telstra — real
    ["example.net.au", "example", "net.au"], // illustrative
    ["example.org.au", "example", "org.au"], // illustrative
    ["unimelb.edu.au", "unimelb", "edu.au"], // University of Melbourne — real
    ["ato.gov.au", "ato", "gov.au"], // Australian Taxation Office — real
    ["example.id.au", "example", "id.au"], // illustrative, real .id.au personal suffix
    // Japan
    ["sony.co.jp", "sony", "co.jp"], // Sony — real
    ["example.or.jp", "example", "or.jp"], // illustrative
    ["example.ne.jp", "example", "ne.jp"], // illustrative
    ["u-tokyo.ac.jp", "u-tokyo", "ac.jp"], // University of Tokyo — real
    ["kantei.go.jp", "kantei", "go.jp"], // Japanese Cabinet Office — real
    // New Zealand
    ["trademe.co.nz", "trademe", "co.nz"], // Trade Me — real
    ["example.net.nz", "example", "net.nz"], // illustrative
    ["example.org.nz", "example", "org.nz"], // illustrative
    // Others in common use
    ["mtn.co.za", "mtn", "co.za"], // MTN — real
    ["globo.com.br", "globo", "com.br"], // Globo — real
    ["sina.com.cn", "sina", "com.cn"], // Sina — real
    ["banorte.com.mx", "banorte", "com.mx"], // Banorte — real
    ["example.co.in", "example", "co.in"], // illustrative, real .co.in suffix
  ];

  it.each(SUFFIX_FIXTURES)("%s -> sld/tld under its multi-part suffix", (domain, sld, tld) => {
    expect(splitSldTld(domain)).toEqual({ sld, tld });
  });

  it("covers every suffix in MULTI_PART_SUFFIXES (completeness control)", () => {
    // Control: the rows above only prove the suffixes they name. This fails when
    // the fixture set and the real set diverge — a suffix added without a fixture,
    // or a fixture pointing at a suffix that was removed.
    const fixtureTlds = new Set(SUFFIX_FIXTURES.map(([, , tld]) => tld));
    expect(fixtureTlds).toEqual(new Set(MULTI_PART_SUFFIXES));
    expect(MULTI_PART_SUFFIXES.size).toBe(28);
  });
});

// ---------------------------------------------------------------------------
// clampTtl
// ---------------------------------------------------------------------------

describe("clampTtl: contract floor and fallback", () => {
  it("returns a comfortably-large TTL unchanged", () => {
    // Prevents forcing the `t < MIN_TTL` conditional true (L132): if it always
    // clamped, 3600 would come back as MIN_TTL and every record's TTL would floor.
    expect(clampTtl(3600)).toBe(3600);
  });

  it("floors a below-minimum TTL to MIN_TTL", () => {
    expect(clampTtl(100)).toBe(MIN_TTL);
    expect(MIN_TTL).toBe(300);
  });

  it("leaves a TTL exactly at the floor unchanged", () => {
    // Boundary: MIN_TTL itself is not below the floor, so it passes through.
    expect(clampTtl(300)).toBe(300);
  });

  it("applies the fallback when the TTL is unset", () => {
    expect(clampTtl(undefined)).toBe(3600);
    expect(clampTtl(undefined, 900)).toBe(900);
  });
});

// ---------------------------------------------------------------------------
// normalizeFqdn
// ---------------------------------------------------------------------------

describe("normalizeFqdn", () => {
  it("trims surrounding whitespace before appending the dot", () => {
    // Prevents dropping .trim() (L140 MethodExpression): a padded target would
    // otherwise become "  mx.example.com  ." with the spaces baked in.
    expect(normalizeFqdn("  mx.example.com  ")).toBe("mx.example.com.");
  });

  it("appends exactly one trailing dot to a bare host", () => {
    expect(normalizeFqdn("mx.example.com")).toBe("mx.example.com.");
  });

  it("returns the null-MX dot for both the dot and the empty string", () => {
    // Documents that the empty string and "." both resolve to ".". The explicit
    // guard on line 141 and the fall-through path produce the identical result
    // here, which is why the guard's own condition mutants are equivalent (see
    // the report). This pins the observable behavior regardless.
    expect(normalizeFqdn(".")).toBe(".");
    expect(normalizeFqdn("")).toBe(".");
  });
});

// ---------------------------------------------------------------------------
// resolveVars over a batch
// ---------------------------------------------------------------------------

describe("resolveVarsAll", () => {
  const vars: RecordVars = {
    DOMAIN: "example.com",
    SUBDOMAIN: "mail",
    SLD: "example",
    TLD: "com",
    emailProviderSPF: "include:_spf.google.com",
  };

  it("resolves variables in every record of the batch", () => {
    // Covers resolveVarsAll, which the existing suite never called (L169
    // BlockStatement -> {} and L170 ArrowFunction -> () => undefined). An emptied
    // body returns undefined; a neutered map yields [undefined, undefined].
    const records: DnsRecord[] = [
      { type: "CNAME", host: "{SUBDOMAIN}.{DOMAIN}", value: "{SLD}.{TLD}.cdn.net", ttl: 300 },
      { type: "TXT", host: "@", value: "v=spf1 {emailProviderSPF} ~all", ttl: 300 },
    ];
    const out = resolveVarsAll(records, vars);
    expect(out).toHaveLength(2);
    expect(out[0]!.host).toBe("mail.example.com");
    expect(out[0]!.value).toBe("example.com.cdn.net");
    expect(out[1]!.value).toBe("v=spf1 include:_spf.google.com ~all");
  });

  it("returns an empty array for an empty batch (negative control)", () => {
    expect(resolveVarsAll([], vars)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// deriveVars with no options
// ---------------------------------------------------------------------------

describe("deriveVars: called with no options bag", () => {
  it("defaults SUBDOMAIN to empty and leaves emailProviderSPF undefined", () => {
    // Pins the optional-chaining on opts (L182 + L187 OptionalChaining): mutating
    // `opts?.x` to `opts.x` throws when no options bag is passed. Also pins the
    // SUBDOMAIN fallback "" (L187 StringLiteral) — a sentinel there would leak
    // "Stryker was here!" into the subdomain of every no-options derivation.
    const v = deriveVars("EXAMPLE.COM.");
    expect(v.DOMAIN).toBe("example.com");
    expect(v.SUBDOMAIN).toBe("");
    expect(v.SLD).toBe("example");
    expect(v.TLD).toBe("com");
    expect(v.emailProviderSPF).toBeUndefined();
  });

  it("resolves emailProviderSPF only when an email provider is supplied", () => {
    const v = deriveVars("shop.co.uk", { emailProvider: "microsoft" });
    expect(v.emailProviderSPF).toBe("include:spf.protection.outlook.com");
    expect(v.SUBDOMAIN).toBe("");
  });
});
