// Mutation-directed tests for src/connect/plan.ts.
//
// Companion to plan.test.ts: that suite proves the happy-path behaviour reads
// well; this one pins the edges a mutant slips through — host canonicalization,
// subdomain/owner normalization, the merge/clobber guards, purpose
// classification, and the ttl/tag spreads. Each test names the defect it
// prevents. Negative controls are paired with every positive so a test cannot
// pass against a function that always returns the "yes" answer.

import { describe, expect, it } from "vitest";
import type { DnsRecord } from "../../src/types";
import {
  planEmailRecords,
  planFromResolvedRecords,
  planSiteRecords,
} from "../../src/connect/plan";

const byPurpose = (rs: DnsRecord[], p: string) => rs.filter((r) => r.purpose === p);
const hasWarning = (ws: { code: string }[], code: string) => ws.some((w) => w.code === code);

// ---------------------------------------------------------------------------
// canonHost (L36) — host equality must be trailing-dot- AND case-insensitive,
// and must strip ONLY a trailing dot (not the first interior dot).
// Exercised through the DMARC merge, whose existing record carries a trailing
// dot and interior dots ("_dmarc.agent.").
// ---------------------------------------------------------------------------

describe("canonHost / host equality (L36)", () => {
  it("matches an existing DMARC across a trailing dot so the operator's policy is preserved", () => {
    // Prevents: canonHost returning host unchanged (no trim/replace/lowercase),
    // replacing /\.$/ with /\./ (which would strip the interior dot and mis-match),
    // and the empty-replacement literal becoming "Stryker was here!".
    const existing: DnsRecord[] = [
      { type: "TXT", host: "_dmarc.agent.", value: "v=DMARC1; p=reject; rua=mailto:x@y.com", ttl: 3600 },
    ];
    const { records, warnings } = planEmailRecords(
      { subdomain: "agent", spfIncludes: [] },
      existing,
    );
    const dmarc = byPurpose(records, "dmarc")[0]!;
    // Existing p=reject wins over the p=none default → proves the host matched.
    expect(dmarc.value).toContain("p=reject");
    expect(hasWarning(warnings, "existing_dmarc")).toBe(true);
  });

  it("negative control: a DMARC at a DIFFERENT host is not matched (defaults to p=none)", () => {
    const existing: DnsRecord[] = [
      { type: "TXT", host: "_dmarc.other.", value: "v=DMARC1; p=reject", ttl: 3600 },
    ];
    const { records, warnings } = planEmailRecords(
      { subdomain: "agent", spfIncludes: [] },
      existing,
    );
    const dmarc = byPurpose(records, "dmarc")[0]!;
    expect(dmarc.value).toContain("p=none");
    expect(dmarc.value).not.toContain("p=reject");
    expect(hasWarning(warnings, "existing_dmarc")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// normalizeSub (L41, L42) — "@"/""/leading+trailing dots collapse to a bare
// lowercased label; "@" collapses to apex "".
// ---------------------------------------------------------------------------

describe("normalizeSub (L41, L42)", () => {
  it("strips leading/trailing dots and lowercases, keeping interior dots", () => {
    // Prevents: dropping trim/replace/toLowerCase (the `sub ?? ""` mutant), and
    // the regex variants that strip too little (a single leading/trailing dot)
    // or too much (interior dots). "..Ag.ent.." must normalize to "ag.ent".
    const { records } = planEmailRecords(
      { subdomain: "..Ag.ent..", spfIncludes: ["include:_spf.resend.com"] },
      [],
    );
    expect(byPurpose(records, "spf")[0]!.host).toBe("ag.ent");
  });

  it('"@" collapses to the apex, so DMARC lands at "_dmarc" not "_dmarc.@"', () => {
    // Prevents: the s === "@" ternary always taking the else branch (returning
    // "@"), and its "" then-branch becoming a non-empty literal. The SPF host
    // stays "@" in both readings, so DMARC is the discriminating host.
    const { records } = planEmailRecords({ subdomain: "@", spfIncludes: [] }, []);
    expect(byPurpose(records, "dmarc")[0]!.host).toBe("_dmarc");
    expect(byPurpose(records, "spf")[0]!.host).toBe("@");
  });
});

// ---------------------------------------------------------------------------
// ownerFor (L47, L48) — a leaf under a subdomain composes "<leaf>.<sub>";
// leaf "@"/"" collapses to the sub itself.
// ---------------------------------------------------------------------------

describe("ownerFor (L47, L48)", () => {
  it("hosts the SPF identity at the bare subdomain, not '@.agent' or a literal", () => {
    // Prevents: the base ternary flipping (base = leaf instead of "") which would
    // yield "@.agent", the "" then-branch becoming "Stryker was here!", and the
    // `if (sub === "")` guard becoming always-true (which would force the apex
    // branch and return "@" for a subdomain identity).
    const { records } = planEmailRecords(
      { subdomain: "agent", spfIncludes: ["include:_spf.resend.com"] },
      [],
    );
    expect(byPurpose(records, "spf")[0]!.host).toBe("agent");
  });

  it("negative control: an apex identity hosts SPF at '@'", () => {
    const { records } = planEmailRecords({ subdomain: "", spfIncludes: [] }, []);
    expect(byPurpose(records, "spf")[0]!.host).toBe("@");
  });
});

// ---------------------------------------------------------------------------
// txtAt (L59) — only TXT records at the host feed the SPF merge.
// ---------------------------------------------------------------------------

describe("txtAt (L59)", () => {
  it("ignores a non-TXT record whose value merely looks like SPF", () => {
    // Prevents: the type-filter becoming always-true, which would fold an A
    // record's SPF-shaped value into the merge and warn existing_spf.
    const existing: DnsRecord[] = [
      { type: "A", host: "agent", value: "v=spf1 include:_spf.evil.com -all", ttl: 3600 },
    ];
    const { records, warnings } = planEmailRecords(
      { subdomain: "agent", spfIncludes: ["include:_spf.resend.com"] },
      existing,
    );
    const spf = byPurpose(records, "spf")[0]!;
    expect(spf.value).not.toContain("evil");
    expect(spf.value).toContain("~all"); // novice-safe default, not the A record's -all
    expect(hasWarning(warnings, "existing_spf")).toBe(false);
  });

  it("negative control: a real TXT SPF at the host IS merged", () => {
    const existing: DnsRecord[] = [
      { type: "TXT", host: "agent", value: "v=spf1 include:_spf.evil.com -all", ttl: 3600 },
    ];
    const { records, warnings } = planEmailRecords(
      { subdomain: "agent", spfIncludes: ["include:_spf.resend.com"] },
      existing,
    );
    expect(byPurpose(records, "spf")[0]!.value).toContain("evil");
    expect(hasWarning(warnings, "existing_spf")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// mxTargetsAt (L65-L68) — only MX records at the host count, empty/"." targets
// are dropped, targets are trailing-dot-stripped for the warning detail.
// ---------------------------------------------------------------------------

describe("mxTargetsAt (L65-L68)", () => {
  it("names the incumbent MX target cleanly (trailing dot stripped) in the warning", () => {
    // Prevents: the target-map dropping .trim()/.replace (leaving "com.." in the
    // detail), replacing /\.$/ with /\./ (corrupting "aspmx" → "aspmxl"), and the
    // empty-replacement literal turning into "Stryker was here!".
    const existing: DnsRecord[] = [
      { type: "MX", host: "@", value: "aspmx.l.google.com.", ttl: 3600, priority: 1 },
    ];
    const { warnings } = planEmailRecords(
      { subdomain: "", spfIncludes: [], mx: [{ priority: 10, target: "mx.resend.com" }] },
      existing,
    );
    const mxWarn = warnings.find((w) => w.code === "existing_mx")!;
    expect(mxWarn).toBeDefined();
    // Exactly one dot then " Confirm" — a kept trailing dot would read "com.. Confirm".
    expect(mxWarn.detail).toContain("aspmx.l.google.com. Confirm");
    expect(mxWarn.detail).not.toContain("Stryker");
  });

  it("excludes non-MX records and empty/'.' targets from the clobber check", () => {
    // Prevents: the MX-type filter becoming always-true (a TXT would count as a
    // live mail provider), and the trailing `v.length > 0 && v !== "."` filter
    // being weakened so a null-MX "." (→ "") or ".." (→ ".") falsely trips the guard.
    const existing: DnsRecord[] = [
      { type: "TXT", host: "@", value: "v=spf1 include:_spf.google.com ~all", ttl: 3600 },
      { type: "MX", host: "@", value: ".", ttl: 3600, priority: 0 },
      { type: "MX", host: "@", value: "..", ttl: 3600, priority: 5 },
    ];
    const { warnings } = planEmailRecords(
      { subdomain: "", spfIncludes: [], mx: [{ priority: 10, target: "mx.resend.com" }] },
      existing,
    );
    expect(hasWarning(warnings, "existing_mx")).toBe(false);
  });

  it("negative control: a real incumbent MX at the apex DOES trip the guard", () => {
    const existing: DnsRecord[] = [
      { type: "MX", host: "@", value: "aspmx.l.google.com.", ttl: 3600, priority: 1 },
    ];
    const { warnings } = planEmailRecords(
      { subdomain: "", spfIncludes: [], mx: [{ priority: 10, target: "mx.resend.com" }] },
      existing,
    );
    expect(hasWarning(warnings, "existing_mx")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// typesAt (L72, L74) — feeds the DKIM RFC-1034 CNAME-coexistence guard, scoped
// to the DKIM selector host only.
// ---------------------------------------------------------------------------

describe("typesAt drives the DKIM coexistence guard (L72, L74)", () => {
  it("refuses a DKIM CNAME where a TXT already exists at the selector label", () => {
    // Prevents: an empty typesAt body (returns undefined → guard never fires),
    // and the host filter collapsing so the label's real types are lost.
    expect(() =>
      planEmailRecords(
        {
          subdomain: "agent",
          spfIncludes: [],
          dkim: [{ selector: "resend", recordType: "CNAME", value: "resend._domainkey.resend.com." }],
        },
        [{ type: "TXT", host: "resend._domainkey.agent", value: "existing=1", ttl: 3600 }],
      ),
    ).toThrow();
  });

  it("refuses a DKIM TXT where a CNAME already exists at the selector label", () => {
    // Prevents: the map callback returning undefined (types = [undefined] →
    // includes("CNAME") is false → guard silently passes).
    expect(() =>
      planEmailRecords(
        {
          subdomain: "agent",
          spfIncludes: [],
          dkim: [{ selector: "google", recordType: "TXT", value: "v=DKIM1; k=rsa; p=MIIB" }],
        },
        [{ type: "CNAME", host: "google._domainkey.agent", value: "dkim.google.com.", ttl: 3600 }],
      ),
    ).toThrow();
  });

  it("allows a DKIM CNAME when the conflicting type sits at a DIFFERENT host", () => {
    // Prevents: the host filter becoming always-true or inverted so unrelated
    // records at other hosts are reported at the selector label and over-refuse.
    const { records } = planEmailRecords(
      {
        subdomain: "agent",
        spfIncludes: [],
        dkim: [{ selector: "resend", recordType: "CNAME", value: "resend._domainkey.resend.com." }],
      },
      [{ type: "TXT", host: "@", value: "some=verification", ttl: 3600 }],
    );
    const dkim = byPurpose(records, "dkim")[0]!;
    expect(dkim.host).toBe("resend._domainkey.agent");
    expect(dkim.type).toBe("CNAME");
  });
});

// ---------------------------------------------------------------------------
// planEmailRecords MX gate (L119) and DMARC tag/ttl spreads (L144-L147).
// ---------------------------------------------------------------------------

describe("planEmailRecords MX gate (L119)", () => {
  it("writes no MX and does not throw for a send-only identity", () => {
    // Prevents: the `plan.mx && plan.mx.length > 0` guard becoming always-true,
    // which would call buildMx with undefined entries and throw.
    const { records } = planEmailRecords({ subdomain: "agent", spfIncludes: [] }, []);
    expect(byPurpose(records, "mx")).toHaveLength(0);
  });

  it("does not warn existing_mx when the requested MX set is empty", () => {
    // Prevents: the length comparison becoming `>= 0`, which would enter the MX
    // branch for an empty set and fire the clobber warning though nothing is written.
    const existing: DnsRecord[] = [
      { type: "MX", host: "@", value: "aspmx.l.google.com.", ttl: 3600, priority: 1 },
    ];
    const { records, warnings } = planEmailRecords(
      { subdomain: "", spfIncludes: [], mx: [] },
      existing,
    );
    expect(byPurpose(records, "mx")).toHaveLength(0);
    expect(hasWarning(warnings, "existing_mx")).toBe(false);
  });
});

describe("planEmailRecords DMARC tags + ttl (L144-L147)", () => {
  it("applies caller-supplied DMARC tags when there is no existing policy", () => {
    // Prevents: the `plan.dmarcTags` spread being dropped (mergeDmarc would fall
    // back to the p=none default).
    const { records } = planEmailRecords(
      { subdomain: "agent", spfIncludes: [], dmarcTags: { p: "quarantine" } },
      [],
    );
    const dmarc = byPurpose(records, "dmarc")[0]!;
    expect(dmarc.value).toContain("p=quarantine");
    expect(dmarc.value).not.toContain("p=none");
  });

  it("threads the caller ttl onto the SPF and DMARC records", () => {
    // Prevents: the ttl spread being dropped (falls back to the 3600 clamp default).
    const { records } = planEmailRecords(
      { subdomain: "agent", spfIncludes: [], ttl: 1500 },
      [],
    );
    expect(byPurpose(records, "spf")[0]!.ttl).toBe(1500);
    expect(byPurpose(records, "dmarc")[0]!.ttl).toBe(1500);
  });

  it("negative control: default DMARC ttl is the 3600 clamp when no ttl is given", () => {
    const { records } = planEmailRecords({ subdomain: "agent", spfIncludes: [] }, []);
    expect(byPurpose(records, "dmarc")[0]!.ttl).toBe(3600);
  });
});

// ---------------------------------------------------------------------------
// planFromResolvedRecords — classification of a caller-supplied resolved set.
// ---------------------------------------------------------------------------

describe("planFromResolvedRecords: SPF folding (L182, L184, L189, L193)", () => {
  it("trims and classifies an SPF value carrying surrounding whitespace", () => {
    // Prevents: dropping the .trim() so a leading-space "v=spf1 …" fails the
    // regex and is mis-routed to passthrough.
    const { records } = planFromResolvedRecords(
      [{ type: "TXT", host: "send", value: "  v=spf1 include:amazonses.com ~all  ", ttl: 3600 }],
      [],
    );
    const spf = byPurpose(records, "spf");
    expect(spf).toHaveLength(1);
    expect(spf[0]!.value).toContain("include:amazonses.com");
  });

  it("classifies a bare 'v=spf1' (no mechanisms) as SPF", () => {
    // Prevents: the regex losing its `|$` alternative, which would only match
    // "v=spf1" followed by whitespace.
    const { records } = planFromResolvedRecords(
      [{ type: "TXT", host: "send", value: "v=spf1", ttl: 3600 }],
      [],
    );
    expect(byPurpose(records, "spf")).toHaveLength(1);
  });

  it("drops the caller's 'all' term instead of adopting a hard -all on a fresh record", () => {
    // Prevents: the additions filter that strips the `all` mechanism being
    // weakened, which would carry a caller's -all into a brand-new record instead
    // of the novice-safe ~all default.
    const { records } = planFromResolvedRecords(
      [{ type: "TXT", host: "send", value: "v=spf1 include:amazonses.com -all", ttl: 3600 }],
      [],
    );
    expect(byPurpose(records, "spf")[0]!.value).toBe("v=spf1 include:amazonses.com ~all");
  });

  it("threads the resolved SPF record's ttl through the merge", () => {
    // Prevents: the rec.ttl spread being dropped (falls back to the 3600 clamp).
    const { records } = planFromResolvedRecords(
      [{ type: "TXT", host: "send", value: "v=spf1 include:amazonses.com ~all", ttl: 700 }],
      [],
    );
    expect(byPurpose(records, "spf")[0]!.ttl).toBe(700);
  });

  it("negative control: without ttl the merged SPF falls to the 3600 clamp", () => {
    const { records } = planFromResolvedRecords(
      [{ type: "TXT", host: "send", value: "v=spf1 include:amazonses.com ~all" } as DnsRecord],
      [],
    );
    expect(byPurpose(records, "spf")[0]!.ttl).toBe(3600);
  });
});

describe("planFromResolvedRecords: DMARC merge (L200-L206)", () => {
  it("does NOT treat a plain verification TXT as a DMARC record", () => {
    // Prevents: the `type === "TXT" && v=DMARC1` guard becoming an OR (every TXT
    // would be rewritten into a p=none DMARC policy).
    const { records } = planFromResolvedRecords(
      [{ type: "TXT", host: "label", value: "google-site-verification=abc123", ttl: 3600 }],
      [],
    );
    const rec = records[0]!;
    expect(rec.value).toBe("google-site-verification=abc123");
    expect(rec.purpose).not.toBe("dmarc");
  });

  it("carries the resolved DMARC policy tags through when there is no existing record", () => {
    // Prevents: mergeDmarc being called with {} (parsed tags dropped → p=none).
    const { records } = planFromResolvedRecords(
      [{ type: "TXT", host: "_dmarc.send", value: "v=DMARC1; p=reject", ttl: 3600 }],
      [],
    );
    expect(byPurpose(records, "dmarc")[0]!.value).toContain("p=reject");
  });

  it("preserves an existing DMARC policy over the resolved one", () => {
    // Prevents: the existingTxt spread being dropped/inverted so the operator's
    // policy is overwritten by the caller's.
    const existing: DnsRecord[] = [
      { type: "TXT", host: "_dmarc.send", value: "v=DMARC1; p=quarantine", ttl: 3600 },
    ];
    const { records, warnings } = planFromResolvedRecords(
      [{ type: "TXT", host: "_dmarc.send", value: "v=DMARC1; p=reject", ttl: 3600 }],
      existing,
    );
    const dmarc = byPurpose(records, "dmarc")[0]!;
    expect(dmarc.value).toContain("p=quarantine");
    expect(dmarc.value).not.toContain("p=reject");
    expect(hasWarning(warnings, "existing_dmarc")).toBe(true);
  });

  it("threads the resolved DMARC record's ttl through the merge", () => {
    // Prevents: the rec.ttl spread being dropped on the DMARC path.
    const { records } = planFromResolvedRecords(
      [{ type: "TXT", host: "_dmarc.send", value: "v=DMARC1; p=none", ttl: 900 }],
      [],
    );
    expect(byPurpose(records, "dmarc")[0]!.ttl).toBe(900);
  });
});

describe("planFromResolvedRecords: MX priority + array init (L176, L177, L227, L234)", () => {
  it("preserves an explicit MX priority instead of overwriting it with 10+i", () => {
    // Prevents: `r.priority ?? 10 + i` becoming `r.priority && 10 + i`, which
    // discards the supplied priority.
    const { records } = planFromResolvedRecords(
      [{ type: "MX", host: "send", value: "mx1.example.com", ttl: 3600, priority: 5 }],
      [],
    );
    const mx = records.filter((r) => r.type === "MX");
    expect(mx).toHaveLength(1);
    expect(mx[0]!.priority).toBe(5);
  });

  it("assigns ascending fallback priorities (10, 11) to MX entries missing one", () => {
    // Prevents: the fallback arithmetic becoming 10 - i (yielding 10, 9).
    const recs: DnsRecord[] = [
      { type: "MX", host: "send", value: "mx1.example.com" } as DnsRecord,
      { type: "MX", host: "send", value: "mx2.example.com" } as DnsRecord,
    ];
    const { records } = planFromResolvedRecords(recs, []);
    const priorities = records.filter((r) => r.type === "MX").map((r) => r.priority).sort();
    expect(priorities).toEqual([10, 11]);
  });

  it("threads the resolved MX ttl through buildMx", () => {
    // Prevents: the mxRecs[0].ttl spread being dropped (falls back to 3600).
    const { records } = planFromResolvedRecords(
      [{ type: "MX", host: "send", value: "mx1.example.com", ttl: 800, priority: 10 }],
      [],
    );
    expect(records.find((r) => r.type === "MX")!.ttl).toBe(800);
  });

  it("emits only real records — the output/warning arrays start empty", () => {
    // Prevents: the `out`/`warnings` initializers seeded with a "Stryker was here"
    // string element.
    const { records, warnings } = planFromResolvedRecords(
      [{ type: "A", host: "www", value: "1.2.3.4", ttl: 3600 }],
      [],
    );
    expect(records).toHaveLength(1);
    expect(records[0]!.type).toBe("A");
    expect(warnings).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// classifyPurpose (L245-L247) — passthrough records get a best-effort purpose.
// ---------------------------------------------------------------------------

describe("planFromResolvedRecords: classifyPurpose (L245-L247)", () => {
  const purposeOf = (rec: DnsRecord): string | undefined => {
    const { records } = planFromResolvedRecords([rec], []);
    return records[0]!.purpose;
  };

  it("tags a _domainkey CNAME as dkim", () => {
    // Prevents: the _domainkey guard becoming always-false (would fall through to "site").
    expect(purposeOf({ type: "CNAME", host: "sel._domainkey.send", value: "x.dkim.example.com", ttl: 3600 }))
      .toBe("dkim");
  });

  it("tags a plain CNAME (no _domainkey) as site, not dkim", () => {
    // Prevents: the _domainkey guard becoming always-true.
    expect(purposeOf({ type: "CNAME", host: "cdn", value: "target.example.com", ttl: 3600 }))
      .toBe("site");
  });

  it("tags A and AAAA records as site", () => {
    // Prevents: the A/AAAA arms of the site test flipping to "" / inverted equality
    // / && instead of ||.
    expect(purposeOf({ type: "A", host: "www", value: "1.2.3.4", ttl: 3600 })).toBe("site");
    expect(purposeOf({ type: "AAAA", host: "www", value: "::1", ttl: 3600 })).toBe("site");
  });

  it("tags a non-address, non-dkim record (CAA) as other", () => {
    // Prevents: the "other" fallback literal becoming "", and the site test
    // becoming always-true.
    expect(purposeOf({ type: "CAA", host: "www", value: '0 issue "letsencrypt.org"', ttl: 3600 }))
      .toBe("other");
  });

  it("respects an explicit purpose on a passthrough record", () => {
    // Negative control: classification only applies when purpose is unset.
    expect(purposeOf({ type: "A", host: "www", value: "1.2.3.4", ttl: 3600, purpose: "verification" }))
      .toBe("verification");
  });
});

// ---------------------------------------------------------------------------
// planSiteRecords (L280-L308) — subdomain CNAME, apex flatten/ALIAS, unresolved.
// ---------------------------------------------------------------------------

describe("planSiteRecords ttl + purpose + empty warnings (L280-L304)", () => {
  it("uses the caller ttl on a subdomain CNAME and defaults to 3600 when unset", () => {
    // Prevents: `ttl ?? 3600` becoming `ttl && 3600` (which would force 3600 for
    // any explicit ttl and undefined when unset).
    const withTtl = planSiteRecords(
      { subdomain: "www", target: "pages.gbuild.app", supportsApex: false, ttl: 1800 },
      [],
    );
    expect(withTtl.records[0]!.ttl).toBe(1800);
    expect(withTtl.records[0]!.purpose).toBe("site"); // prevents the purpose literal → ""
    expect(withTtl.warnings).toHaveLength(0); // prevents the [] initializer → ["Stryker was here"]

    const noTtl = planSiteRecords(
      { subdomain: "www", target: "pages.gbuild.app", supportsApex: false },
      [],
    );
    expect(noTtl.records[0]!.ttl).toBe(3600);
  });

  it("apex on a flattening host emits a CNAME at @ with no warnings", () => {
    // Prevents the apex-branch [] warnings initializer becoming non-empty.
    const { records, warnings } = planSiteRecords(
      { subdomain: "", target: "pages.gbuild.app", supportsApex: true, ttl: 2400 },
      [],
    );
    expect(records[0]).toMatchObject({ type: "CNAME", host: "@" });
    expect(records[0]!.ttl).toBe(2400);
    expect(warnings).toHaveLength(0);
  });

  it("apex flatten threads the caller ttl into the A/AAAA records", () => {
    // Prevents: the ttl spread to planApex being dropped (would clamp to 300).
    const { records, warnings } = planSiteRecords(
      { subdomain: "", target: "pages.gbuild.app", supportsApex: false, resolved: { a: ["1.2.3.4"] }, ttl: 1200 },
      [],
    );
    expect(records[0]).toMatchObject({ type: "A", host: "@", value: "1.2.3.4" });
    expect(records[0]!.ttl).toBe(1200);
    expect(warnings).toHaveLength(0);
  });

  it("negative control: apex flatten with no ttl clamps to the 300 floor", () => {
    const { records } = planSiteRecords(
      { subdomain: "", target: "pages.gbuild.app", supportsApex: false, resolved: { a: ["1.2.3.4"] } },
      [],
    );
    expect(records[0]!.ttl).toBe(300);
  });

  it("apex, non-flattening, unresolved → the warning detail carries the resolver reason", () => {
    // Prevents: the `strategy === "unresolved" ? reason : "apex"` ternary flipping
    // to the literal "apex", which would drop the actionable resolve-first message.
    const { records, warnings } = planSiteRecords(
      { subdomain: "", target: "pages.gbuild.app", supportsApex: false },
      [],
    );
    expect(records).toHaveLength(0);
    const warn = warnings.find((w) => w.code === "apex_cname")!;
    expect(warn.detail).toContain("Resolve the target");
    expect(warn.detail).not.toBe("apex");
  });
});
