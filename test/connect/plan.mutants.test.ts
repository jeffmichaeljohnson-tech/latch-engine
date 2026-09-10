// Latch — connect/plan.ts: mutation-hardening tests.
//
// Companion to plan.test.ts. That suite proves the happy paths read well
// (subdomain default, SPF merge, MX clobber-guard, DKIM placement, site records);
// this one pins the edges a mutant slips through. The whole point of a plan is to
// say TRUTHFULLY what WILL change before anything changes, so the strongest
// assertions here aim at the two failures that matter most: a plan reporting an
// operation as applied when it was not (a spurious record, a warning that should
// not fire, a host written to the wrong owner) and a plan omitting an operation
// that will happen (a merge skipped, a clobber-guard silenced, a record dropped).
//
// plan.ts is PURE — it never touches the network. To PROVE that (and to honor the
// no-real-network rule), every test runs with global fetch stubbed to throw; a
// stray call would surface as a failure.
//
// Each test names WHICH defect it prevents, and each group carries a negative
// control so a function that always returns the "yes" answer cannot pass.
//
// EQUIVALENT MUTANTS (deliberately given no test — no observable behavior change):
//   - L36 canonHost `.toLowerCase()` -> `.toUpperCase()`: canonHost is used ONLY
//     inside symmetric equality (both operands are canonicalized), so folding to
//     upper vs lower yields identical equality outcomes.
//   - L47 ownerFor StringLiteral `leaf === ""` -> "Stryker was here!": `leaf` is
//     never "" at any call site (always "@", "_dmarc", or "<sel>._domainkey"), so
//     the mutated comparison never changes `base`.
//   - L109 / L120 StringLiteral `ownerFor("@", sub)` -> `ownerFor("", sub)`:
//     ownerFor maps BOTH "@" and "" to base "", so spfHost/mxHost are identical.
//   - L187 Regex `/\s+/` -> `/\s/`: `value` is trimmed and the following
//     `.filter(t => t !== "")` removes the extra empty tokens a single-space split
//     would produce, so `additions` is identical.
//   - L189 StringLiteral `t !== ""` -> `t !== "Stryker was here!"`: split(/\s+/) of a
//     trimmed string never yields "", so the `t !== ""` guard removes nothing and
//     mutating its literal changes nothing.
//   - L145/146/147, L193, L204, L206, L234, L301 ConditionalExpression -> true: each
//     spreads `{ key: undefined }` when the source is undefined; mergeSpf / mergeDmarc
//     / buildMx / planApex all treat a present-but-undefined field exactly like an
//     absent one (`clampTtl(undefined)`, `if (input.tags)`, `!== undefined` checks).
//   - L234 OptionalChaining `mxRecs[0]?.ttl` -> `mxRecs[0].ttl`: mxByHost only ever
//     holds non-empty arrays (a record is pushed before the map is set), so
//     `mxRecs[0]` is always defined.
//   - L300 ConditionalExpression -> true: passing `{ resolved: undefined }` vs
//     omitting it is identical to planApex (`input.resolved?.a ?? []`).
//   - L308 ConditionalExpression -> true and its false-branch "apex" StringLiteral:
//     at line 308 `apex.strategy` is invariantly "unresolved" (the flatten path
//     returns earlier and the alias path needs supportsApex, handled above), so the
//     condition is always true and the "apex" literal is never emitted.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  planEmailRecords,
  planFromResolvedRecords,
  planSiteRecords,
} from "../../src/connect/plan";
import { LatchError } from "../../src/types";
import type { DnsRecord } from "../../src/types";

const byPurpose = (rs: DnsRecord[], p: string) => rs.filter((r) => r.purpose === p);
const first = (rs: DnsRecord[], p: string) => byPurpose(rs, p)[0]!;
const hasWarn = (ws: { code: string }[], code: string) => ws.some((w) => w.code === code);

// PROOF OF PURITY: any accidental network call throws and fails the test.
beforeEach(() => {
  vi.stubGlobal(
    "fetch",
    vi.fn(() => {
      throw new Error("plan.ts must never call the network");
    }),
  );
});
afterEach(() => vi.unstubAllGlobals());

// ===========================================================================
// normalizeSub — subdomain normalization (src L40-43), observed as the SPF host.
// ===========================================================================
describe("normalizeSub (via planEmailRecords host)", () => {
  const spfHostFor = (subdomain?: string) =>
    first(planEmailRecords({ subdomain, spfIncludes: [] }, []).records, "spf").host;

  it("trims, strips leading/trailing dots, and lower-cases", () => {
    // Prevents L41 MethodExpression (`sub ?? ""` — the whole .trim().replace().toLowerCase()
    // dropped) and the `.replace(…, "")` StringLiteral -> "Stryker was here!".
    expect(spfHostFor(".Agent.")).toBe("agent");
  });

  it("keeps an interior dot (only leading/trailing dots are stripped)", () => {
    // Prevents the `^` anchor being dropped from the first alternative and the `$`
    // from the second (`/\.+|\.+$/g`, `/^\.+|\.+/g`) — either would strip the middle
    // dot, collapsing "a.b" to "ab".
    expect(spfHostFor("a.b")).toBe("a.b");
  });

  it("strips MORE THAN ONE leading dot", () => {
    // Prevents the `+` in the first alternative being reduced to a single char
    // (`/^\.|\.+$/g`), which would leave ".agent".
    expect(spfHostFor("..agent")).toBe("agent");
  });

  it("strips MORE THAN ONE trailing dot", () => {
    // Prevents the `+` in the second alternative being reduced to a single char
    // (`/^\.+|\.$/g`), which would leave "agent.".
    expect(spfHostFor("agent..")).toBe("agent");
  });

  it("an omitted subdomain resolves to the apex, not to a literal", () => {
    // Prevents L41 `(sub ?? "")` -> `(sub ?? "Stryker was here!")`: an undefined
    // subdomain must collapse to the apex "@", never to "stryker was here!".
    const { records } = planEmailRecords({ spfIncludes: [] }, []);
    expect(first(records, "spf").host).toBe("@");
  });

  it('"@" is treated as the apex for BOTH a "@"-leaf and a named leaf', () => {
    // Prevents L42 `s === "@" ? "" : s`:
    //   -> ConditionalExpression false (always returns s): the DMARC host becomes
    //      "_dmarc.@" instead of "_dmarc".
    //   -> StringLiteral "" -> "Stryker was here!": both hosts gain the literal.
    const { records } = planEmailRecords({ subdomain: "@", spfIncludes: [] }, []);
    expect(first(records, "spf").host).toBe("@");
    expect(first(records, "dmarc").host).toBe("_dmarc"); // NOT "_dmarc.@"
  });
});

// ===========================================================================
// ownerFor — owner-name assembly (src L46-50), observed via SPF + DMARC hosts.
// ===========================================================================
describe("ownerFor (via planEmailRecords hosts)", () => {
  it("nests a named leaf under a subdomain and collapses the '@'-leaf to the bare sub", () => {
    // Prevents L48 `if (sub === "")` -> true (which would force the apex branch and
    // return "@"/base for a real subdomain) and L47 ConditionalExpression -> false
    // (base = leaf, giving "@.agent" for the SPF host).
    const { records } = planEmailRecords({ subdomain: "agent", spfIncludes: [] }, []);
    expect(first(records, "spf").host).toBe("agent"); // "@"-leaf collapses to the sub
    expect(first(records, "dmarc").host).toBe("_dmarc.agent"); // named leaf nests
  });

  it("NEGATIVE CONTROL: at the apex the '@'-leaf is '@' and a named leaf stays bare", () => {
    const { records } = planEmailRecords({ subdomain: "", spfIncludes: [] }, []);
    expect(first(records, "spf").host).toBe("@");
    expect(first(records, "dmarc").host).toBe("_dmarc");
  });
});

// ===========================================================================
// canonHost + typesAt — the DKIM CNAME-coexistence guard (src L34-37, L72-74).
// typesAt is reached only through the DKIM branch; a conflict makes buildDkim throw.
// ===========================================================================
describe("canonHost + typesAt (via DKIM coexistence guard)", () => {
  const dkimCname = {
    subdomain: "agent",
    spfIncludes: [] as string[],
    dkim: [{ selector: "resend", recordType: "CNAME" as const, value: "cname.target." }],
  };

  it("throws when a non-CNAME already occupies the selector label (case- and dot-insensitive)", () => {
    // The existing record's host is upper-cased, trailing-dotted and multi-label, so
    // this one throw prevents EVERY canonHost mutant: identity (`host`), Regex
    // `/\.$/` -> `/\./` (would drop an interior dot instead of the trailing one), and
    // the replace StringLiteral -> "Stryker was here!". It also prevents L72
    // BlockStatement -> {} (typesAt returns undefined -> no guard), L74 EqualityOperator
    // `!==`, and filter ConditionalExpression -> false (no match -> no guard).
    const existing: DnsRecord[] = [
      { type: "A", host: "RESEND._domainkey.AGENT.", value: "1.2.3.4", ttl: 300 },
    ];
    let err: unknown;
    try {
      planEmailRecords(dkimCname, existing);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(LatchError);
    expect((err as LatchError).code).toBe("unsupported");
  });

  it("does NOT throw when the conflicting record sits at a DIFFERENT label", () => {
    // Prevents L74 filter ConditionalExpression -> true (all hosts matched) and
    // MethodExpression -> `existing` (returns the record objects, so `some(o => o !==
    // "CNAME")` is true for ANY existing record). Here the A record is at a different
    // _domainkey label, so a correct typesAt returns [] and nothing throws.
    const existing: DnsRecord[] = [
      { type: "A", host: "other._domainkey.agent", value: "1.2.3.4", ttl: 300 },
    ];
    const { records } = planEmailRecords(dkimCname, existing);
    const dkim = first(records, "dkim");
    expect(dkim.host).toBe("resend._domainkey.agent");
    expect(dkim.type).toBe("CNAME");
  });

  it("a DKIM CNAME COEXISTS with an existing CNAME at the same label (no throw)", () => {
    // Prevents L74 map ArrowFunction -> `() => undefined`: the real types must reach
    // buildDkim. With a mutated map, typesAt yields [undefined]; `some(t => t !==
    // "CNAME")` is then true and this legal CNAME+CNAME case would wrongly throw.
    const existing: DnsRecord[] = [
      { type: "CNAME", host: "resend._domainkey.agent", value: "old.target.", ttl: 300 },
    ];
    expect(() => planEmailRecords(dkimCname, existing)).not.toThrow();
  });

  it("a DKIM TXT is rejected when a CNAME already occupies the label", () => {
    // Also prevents L74 map -> `() => undefined`: buildDkim's TXT path checks
    // `existing.includes("CNAME")`, which needs the literal "CNAME" type — [undefined]
    // would not include it and the illegal coexistence would slip through.
    const existing: DnsRecord[] = [
      { type: "CNAME", host: "resend._domainkey.agent", value: "old.target.", ttl: 300 },
    ];
    const txtPlan = {
      subdomain: "agent",
      spfIncludes: [] as string[],
      dkim: [{ selector: "resend", recordType: "TXT" as const, value: "v=DKIM1; p=abc" }],
    };
    expect(() => planEmailRecords(txtPlan, existing)).toThrow(LatchError);
  });
});

// ===========================================================================
// txtAt — selecting the existing SPF to merge into (src L57-59).
// ===========================================================================
describe("txtAt (existing-SPF selection)", () => {
  it("ignores a v=spf1 TXT that lives at a DIFFERENT host", () => {
    // Prevents L59 filter ConditionalExpression -> true (which would pull in TXTs
    // from every host): an apex SPF must not be folded into a subdomain identity.
    const existing: DnsRecord[] = [
      { type: "TXT", host: "@", value: "v=spf1 include:_spf.foreign.com -all", ttl: 3600 },
    ];
    const { records, warnings } = planEmailRecords(
      { subdomain: "agent", spfIncludes: ["include:_spf.resend.com"] },
      existing,
    );
    expect(first(records, "spf").value).not.toContain("_spf.foreign.com");
    expect(hasWarn(warnings, "existing_spf")).toBe(false);
  });

  it("ignores a non-TXT record even at the identity host", () => {
    // Prevents L59 dropping the `r.type === "TXT"` half: an MX that happens to carry
    // an spf-shaped value must NOT be treated as an existing SPF record.
    const existing: DnsRecord[] = [
      { type: "MX", host: "agent", value: "v=spf1 include:_spf.foreign.com ~all", ttl: 3600, priority: 1 },
    ];
    const { records, warnings } = planEmailRecords(
      { subdomain: "agent", spfIncludes: ["include:_spf.resend.com"] },
      existing,
    );
    expect(first(records, "spf").value).not.toContain("_spf.foreign.com");
    expect(hasWarn(warnings, "existing_spf")).toBe(false);
  });

  it("NEGATIVE CONTROL: a case-differing existing SPF at the identity host DOES merge", () => {
    // Proves the filter is not "always false" AND exercises canonHost's case-fold on
    // the SPF path: an upper-case existing host must still match the lower-case
    // identity so the real SPF is merged (never a second v=spf1).
    const existing: DnsRecord[] = [
      { type: "TXT", host: "AGENT", value: "v=spf1 include:_spf.google.com ~all", ttl: 3600 },
    ];
    const { records, warnings } = planEmailRecords(
      { subdomain: "agent", spfIncludes: ["include:_spf.resend.com"] },
      existing,
    );
    expect(first(records, "spf").value).toBe(
      "v=spf1 include:_spf.google.com include:_spf.resend.com ~all",
    );
    expect(hasWarn(warnings, "existing_spf")).toBe(true);
  });
});

// ===========================================================================
// mxTargetsAt — the clobber-guard's incumbent-MX detection (src L63-68).
// ===========================================================================
describe("mxTargetsAt (via the MX clobber-guard)", () => {
  const apexMxPlan = {
    subdomain: "",
    spfIncludes: [] as string[],
    mx: [{ priority: 10, target: "mx.resend.com" }],
  };

  it("counts only real MX at the identity host", () => {
    // Prevents L66 filter ConditionalExpression -> true and dropping the type/host
    // filter: a foreign A record and an MX at another host must not read as an
    // incumbent mail provider at the apex.
    const existing: DnsRecord[] = [
      { type: "A", host: "@", value: "1.2.3.4", ttl: 300 },
      { type: "MX", host: "elsewhere", value: "mx.elsewhere.net.", ttl: 300, priority: 5 },
    ];
    expect(hasWarn(planEmailRecords(apexMxPlan, existing).warnings, "existing_mx")).toBe(false);
  });

  it("ignores null-MX and dot-only targets (they receive no mail)", () => {
    // Prevents L65 dropping the final `.filter(v => v.length > 0 && v !== ".")`, L68
    // EqualityOperator `length >= 0`, L68 LogicalOperator `||`, L68 StringLiteral
    // `v !== "."` -> `v !== ""`, and L68 ConditionalExpression -> true. An RFC 7505
    // null-MX ("." -> "" after the trailing-dot strip) and a ".." target ("." after
    // the strip) are NOT live mail and must raise no clobber warning.
    const existing: DnsRecord[] = [
      { type: "MX", host: "@", value: ".", ttl: 300, priority: 0 },
      { type: "MX", host: "@", value: "..", ttl: 300, priority: 1 },
    ];
    expect(hasWarn(planEmailRecords(apexMxPlan, existing).warnings, "existing_mx")).toBe(false);
  });

  it("reports the incumbent targets with the trailing dot stripped", () => {
    // Prevents L67 MethodExpression -> `r.value` (keeps the trailing dot), Regex
    // `/\.$/` -> `/\./` (strips an interior dot), and StringLiteral "" -> "Stryker
    // was here!". Two dotted targets force a ", " join, so the clean "mx1.test.net,"
    // fragment appears only when the value was normalized correctly.
    const existing: DnsRecord[] = [
      { type: "MX", host: "@", value: "mx1.test.net.", ttl: 300, priority: 1 },
      { type: "MX", host: "@", value: "mx2.test.net.", ttl: 300, priority: 2 },
    ];
    const warn = planEmailRecords(apexMxPlan, existing).warnings.find((w) => w.code === "existing_mx")!;
    expect(warn).toBeDefined();
    expect(warn.detail).toContain("mx1.test.net,");
    expect(warn.detail).toContain("mx2.test.net");
  });

  it("NEGATIVE CONTROL: a real incumbent MX at the apex DOES warn", () => {
    // Proves the guard is not silently disabled by the cases above.
    const existing: DnsRecord[] = [
      { type: "MX", host: "@", value: "aspmx.l.google.com.", ttl: 300, priority: 1 },
    ];
    expect(hasWarn(planEmailRecords(apexMxPlan, existing).warnings, "existing_mx")).toBe(true);
  });
});

// ===========================================================================
// planEmailRecords — the MX-emission gate (src L119).
// ===========================================================================
describe("planEmailRecords MX gate", () => {
  it("a send-only identity emits no MX and does not throw", () => {
    // Prevents L119 ConditionalExpression -> true: forcing the guard true runs
    // buildMx with `entries: undefined`, which throws on `for (const … of undefined)`.
    let result: ReturnType<typeof planEmailRecords> | undefined;
    expect(() => {
      result = planEmailRecords({ subdomain: "agent", spfIncludes: [] }, []);
    }).not.toThrow();
    expect(byPurpose(result!.records, "mx")).toHaveLength(0);
  });

  it("an EMPTY mx array does not touch MX (no clobber warning against a live provider)", () => {
    // Prevents L119 EqualityOperator `length > 0` -> `length >= 0`: with `>= 0`, an
    // empty mx array (length 0) would still enter the MX branch and buildMx would
    // raise existing_mx against the incumbent even though zero MX are being written.
    const existing: DnsRecord[] = [
      { type: "MX", host: "@", value: "aspmx.l.google.com.", ttl: 300, priority: 1 },
    ];
    const { records, warnings } = planEmailRecords(
      { subdomain: "", spfIncludes: [], mx: [] },
      existing,
    );
    expect(byPurpose(records, "mx")).toHaveLength(0);
    expect(hasWarn(warnings, "existing_mx")).toBe(false);
  });

  it("NEGATIVE CONTROL: a non-empty mx array DOES emit MX", () => {
    const { records } = planEmailRecords(
      { subdomain: "agent", spfIncludes: [], mx: [{ priority: 10, target: "mx.resend.com" }] },
      [],
    );
    expect(byPurpose(records, "mx").length).toBeGreaterThan(0);
  });
});

// ===========================================================================
// planEmailRecords — the DMARC merge block (src L143-147).
// ===========================================================================
describe("planEmailRecords DMARC merge", () => {
  it("applies caller-supplied DMARC tags to a fresh record", () => {
    // Prevents L144 mergeDmarc argument -> {} (tags ignored) and the L146 tags-spread
    // mutants (ObjectLiteral -> {}, ConditionalExpression -> false, EqualityOperator):
    // a supplied p=quarantine must reach the record instead of the p=none default.
    const { records } = planEmailRecords(
      { subdomain: "agent", spfIncludes: [], dmarcTags: { p: "quarantine" } },
      [],
    );
    expect(first(records, "dmarc").value).toContain("p=quarantine");
  });

  it("NEGATIVE CONTROL: without supplied tags the record defaults to p=none", () => {
    const { records } = planEmailRecords({ subdomain: "agent", spfIncludes: [] }, []);
    expect(first(records, "dmarc").value).toContain("p=none");
    expect(first(records, "dmarc").value).not.toContain("p=quarantine");
  });

  it("honors an explicit TTL on the DMARC record", () => {
    // Prevents the L147 ttl-spread mutants (ConditionalExpression -> false,
    // EqualityOperator): a supplied ttl of 900 must reach the record instead of the
    // clampTtl default of 3600.
    const { records } = planEmailRecords({ subdomain: "agent", spfIncludes: [], ttl: 900 }, []);
    expect(first(records, "dmarc").ttl).toBe(900);
  });

  it("NEGATIVE CONTROL: an omitted TTL falls back to 3600", () => {
    const { records } = planEmailRecords({ subdomain: "agent", spfIncludes: [] }, []);
    expect(first(records, "dmarc").ttl).toBe(3600);
  });

  it("merges into an existing DMARC, preserving the operator's policy", () => {
    // Prevents the L145 existingTxt-spread mutants (ObjectLiteral -> {},
    // ConditionalExpression -> false, EqualityOperator) and L143 ArrowFunction ->
    // `() => undefined`: an existing p=reject must be found, preserved, and warned.
    const existing: DnsRecord[] = [
      { type: "TXT", host: "_dmarc.agent", value: "v=DMARC1; p=reject", ttl: 3600 },
    ];
    const { records, warnings } = planEmailRecords({ subdomain: "agent", spfIncludes: [] }, existing);
    expect(first(records, "dmarc").value).toContain("p=reject");
    expect(hasWarn(warnings, "existing_dmarc")).toBe(true);
  });

  it("trims before matching the existing DMARC (leading whitespace still merges)", () => {
    // Prevents L143 MethodExpression `t.trim()` -> `t`: a leading-space DMARC value
    // would fail the `^v=DMARC1` anchor and be missed, silently dropping the merge.
    const existing: DnsRecord[] = [
      { type: "TXT", host: "_dmarc.agent", value: "  v=DMARC1; p=reject", ttl: 3600 },
    ];
    const { records, warnings } = planEmailRecords({ subdomain: "agent", spfIncludes: [] }, existing);
    expect(first(records, "dmarc").value).toContain("p=reject");
    expect(hasWarn(warnings, "existing_dmarc")).toBe(true);
  });

  it("does NOT treat a TXT that merely CONTAINS v=DMARC1 as the existing policy", () => {
    // Prevents L143 Regex `/^v=DMARC1/i` -> `/v=DMARC1/i`: only a value that BEGINS
    // with v=DMARC1 is the policy. A mid-string match must not preserve a stray
    // p=reject or raise the merge warning.
    const existing: DnsRecord[] = [
      { type: "TXT", host: "_dmarc.agent", value: "note v=DMARC1; p=reject", ttl: 3600 },
    ];
    const { records, warnings } = planEmailRecords({ subdomain: "agent", spfIncludes: [] }, existing);
    expect(first(records, "dmarc").value).toContain("p=none");
    expect(first(records, "dmarc").value).not.toContain("p=reject");
    expect(hasWarn(warnings, "existing_dmarc")).toBe(false);
  });
});

// ===========================================================================
// planFromResolvedRecords — SPF folding of a caller's resolved set (src L182-193).
// ===========================================================================
describe("planFromResolvedRecords — SPF handling", () => {
  it("recognizes an SPF value with leading whitespace", () => {
    // Prevents L182 `rec.value.trim()` -> `rec.value`: an untrimmed value fails the
    // ^v=spf1 anchor and would be passed through as a plain TXT instead of merged.
    const { records } = planFromResolvedRecords(
      [{ type: "TXT", host: "send", value: "  v=spf1 include:amazonses.com ~all", ttl: 3600 }],
      [],
    );
    expect(byPurpose(records, "spf")).toHaveLength(1);
  });

  it("only recognizes SPF at the START of the value", () => {
    // Prevents L184 Regex `/^v=spf1(\s|$)/i` -> `/v=spf1(\s|$)/i`: a value that merely
    // contains v=spf1 mid-string is an unrelated TXT and must pass through verbatim.
    const { records } = planFromResolvedRecords(
      [{ type: "TXT", host: "send", value: "verify=x v=spf1 include:x ~all", ttl: 3600 }],
      [],
    );
    expect(records[0]!.purpose).not.toBe("spf");
    expect(records[0]!.value).toBe("verify=x v=spf1 include:x ~all");
  });

  it("recognizes a bare 'v=spf1' (end-of-string anchor)", () => {
    // Prevents L184 Regex `/^v=spf1(\s|$)/i` -> `/^v=spf1(\s)/i`: dropping the `$`
    // alternative would fail to recognize a version-only SPF record.
    const { records } = planFromResolvedRecords(
      [{ type: "TXT", host: "send", value: "v=spf1", ttl: 3600 }],
      [],
    );
    expect(byPurpose(records, "spf")).toHaveLength(1);
    expect(first(records, "spf").value).toBe("v=spf1 ~all");
  });

  it("strips the caller's 'all' term and the v=spf1 prefix, defaulting to a soft ~all", () => {
    // Prevents L186 MethodExpression -> `value.split(/\s+/).slice(1)` and ->
    // `value.split(/\s+/)` (both drop the additions filter, propagating "-all"), the
    // L189 ConditionalExpression -> true / LogicalOperator `||` (keep the all-term),
    // and the L189 Regex `/^[^-~?+]?all$/i` (negated class no longer matches "-all").
    // The caller's "-all" must NOT be adopted; a first write is novice-safe "~all".
    const { records } = planFromResolvedRecords(
      [{ type: "TXT", host: "send", value: "v=spf1 include:solo.example -all", ttl: 3600 }],
      [],
    );
    expect(first(records, "spf").value).toBe("v=spf1 include:solo.example ~all");
  });

  it("the all-term regex is exact: mechanisms that only touch 'all' are kept, a bare 'all' is dropped", () => {
    // Prevents L189 Regex `/^[-~?+]?all$/i` -> `/[-~?+]?all$/i` (drops ^, would remove
    // "include:_spf.recall"), -> `/^[-~?+]?all/i` (drops $, would remove "allowme"),
    // and -> `/^[-~?+]all$/i` (requires a qualifier, would KEEP the bare "all" and
    // adopt it as the all-term). This is the case the "-all" test above cannot reach.
    const { records } = planFromResolvedRecords(
      [{ type: "TXT", host: "send", value: "v=spf1 include:_spf.recall allowme all", ttl: 3600 }],
      [],
    );
    expect(first(records, "spf").value).toBe("v=spf1 include:_spf.recall allowme ~all");
  });

  it("carries the SPF record's TTL through the fold", () => {
    // Prevents the L193 ttl-spread mutants (ObjectLiteral -> {}, ConditionalExpression
    // -> false, EqualityOperator): a supplied ttl of 1200 must survive, not fall back
    // to the 3600 default.
    const { records } = planFromResolvedRecords(
      [{ type: "TXT", host: "send", value: "v=spf1 include:x ~all", ttl: 1200 }],
      [],
    );
    expect(first(records, "spf").ttl).toBe(1200);
  });
});

// ===========================================================================
// planFromResolvedRecords — DMARC classification + merge (src L200-206).
// ===========================================================================
describe("planFromResolvedRecords — DMARC handling", () => {
  it("does NOT route a non-DMARC TXT into the DMARC branch", () => {
    // Prevents L200 LogicalOperator `&&` -> `||` and ConditionalExpression -> true:
    // a verification TXT must pass through verbatim, never be rewritten as a DMARC record.
    const { records } = planFromResolvedRecords(
      [{ type: "TXT", host: "send", value: "google-site-verification=abc123", ttl: 300 }],
      [],
    );
    expect(records[0]!.value).toBe("google-site-verification=abc123");
    expect(records[0]!.purpose).not.toBe("dmarc");
  });

  it("only matches DMARC at the START of the value", () => {
    // Prevents L200 Regex `/^v=DMARC1/i` -> `/v=DMARC1/i`: a mid-string v=DMARC1 must
    // not be treated as a DMARC policy.
    const { records } = planFromResolvedRecords(
      [{ type: "TXT", host: "send", value: "note v=DMARC1; p=reject", ttl: 300 }],
      [],
    );
    expect(records[0]!.value).toBe("note v=DMARC1; p=reject");
    expect(records[0]!.purpose).not.toBe("dmarc");
  });

  it("merges the caller's DMARC into an existing policy, which wins (trim-tolerant)", () => {
    // Prevents L201 MethodExpression `t.trim()` -> `t` (leading-space existing policy
    // missed), the L204 existingTxt-spread mutants (ObjectLiteral -> {},
    // ConditionalExpression -> false, EqualityOperator), and L201 ArrowFunction ->
    // `() => undefined`. The operator's p=quarantine must be preserved and warned.
    const existing: DnsRecord[] = [
      { type: "TXT", host: "send", value: "  v=DMARC1; p=quarantine", ttl: 300 },
    ];
    const { records, warnings } = planFromResolvedRecords(
      [{ type: "TXT", host: "send", value: "v=DMARC1; p=none;", ttl: 300 }],
      existing,
    );
    expect(first(records, "dmarc").value).toContain("p=quarantine");
    expect(hasWarn(warnings, "existing_dmarc")).toBe(true);
  });

  it("does NOT match an existing DMARC that only CONTAINS v=DMARC1", () => {
    // Prevents L201 Regex `/^v=DMARC1/i` -> `/v=DMARC1/i`: a stray p=reject that is not
    // an anchored DMARC record must not be preserved or warned.
    const existing: DnsRecord[] = [
      { type: "TXT", host: "send", value: "pre v=DMARC1; p=reject", ttl: 300 },
    ];
    const { records, warnings } = planFromResolvedRecords(
      [{ type: "TXT", host: "send", value: "v=DMARC1; p=none;", ttl: 300 }],
      existing,
    );
    expect(first(records, "dmarc").value).toContain("p=none");
    expect(first(records, "dmarc").value).not.toContain("p=reject");
    expect(hasWarn(warnings, "existing_dmarc")).toBe(false);
  });

  it("carries the DMARC record's TTL through the merge", () => {
    // Prevents the L206 ttl-spread mutants (ObjectLiteral -> {}, ConditionalExpression
    // -> false, EqualityOperator).
    const { records } = planFromResolvedRecords(
      [{ type: "TXT", host: "send", value: "v=DMARC1; p=none;", ttl: 1500 }],
      [],
    );
    expect(first(records, "dmarc").ttl).toBe(1500);
  });
});

// ===========================================================================
// planFromResolvedRecords — MX grouping + priority/TTL fallback (src L227-234).
// ===========================================================================
describe("planFromResolvedRecords — MX grouping", () => {
  it("preserves an explicitly-supplied MX priority", () => {
    // Prevents L227 LogicalOperator `r.priority ?? 10 + i` -> `r.priority && 10 + i`:
    // with `&&`, a real priority of 7 is truthy and would be REPLACED by 10.
    const { records } = planFromResolvedRecords(
      [{ type: "MX", host: "send", value: "mx.example", ttl: 300, priority: 7 }],
      [],
    );
    expect(records.find((r) => r.type === "MX")!.priority).toBe(7);
  });

  it("assigns ASCENDING unique fallback priorities to MX missing one", () => {
    // Prevents L227 ArithmeticOperator `10 + i` -> `10 - i`: two priority-less MX must
    // become 10 and 11, not 10 and 9.
    const { records } = planFromResolvedRecords(
      [
        { type: "MX", host: "send", value: "mxa.example", ttl: 300 },
        { type: "MX", host: "send", value: "mxb.example", ttl: 300 },
      ],
      [],
    );
    expect(records.filter((r) => r.type === "MX").map((r) => r.priority)).toEqual([10, 11]);
  });

  it("carries the first MX record's TTL onto the built set", () => {
    // Prevents the L234 ttl-spread mutants (ObjectLiteral -> {}, ConditionalExpression
    // -> false, EqualityOperator).
    const { records } = planFromResolvedRecords(
      [{ type: "MX", host: "send", value: "mx.example", ttl: 2400, priority: 10 }],
      [],
    );
    expect(records.find((r) => r.type === "MX")!.ttl).toBe(2400);
  });
});

// ===========================================================================
// planFromResolvedRecords — passthrough + classifyPurpose (src L176-177, 221, 244-247).
// ===========================================================================
describe("planFromResolvedRecords — passthrough + classifyPurpose", () => {
  it("classifies each passthrough record by host then type", () => {
    // Prevents L245 ConditionalExpression -> true (everything -> "dkim"), the whole
    // L246 A/AAAA/CNAME condition family (each equality, each string literal, each
    // logical operator, and the true/false forcings), and L247 `return "other"` -> "".
    const { records } = planFromResolvedRecords(
      [
        { type: "A", host: "@", value: "1.2.3.4", ttl: 300 },
        { type: "AAAA", host: "@", value: "2606::1", ttl: 300 },
        { type: "CNAME", host: "www", value: "site.example.", ttl: 300 },
        { type: "CAA", host: "@", value: '0 issue "letsencrypt.org"', ttl: 300 },
        { type: "NS", host: "deleg", value: "ns1.example.", ttl: 300 },
        { type: "CNAME", host: "sel._domainkey.mail", value: "dk.example.", ttl: 300 },
      ],
      [],
    );
    const purposeOf = (value: string) => records.find((r) => r.value === value)!.purpose;
    expect(purposeOf("1.2.3.4")).toBe("site"); // A -> site
    expect(purposeOf("2606::1")).toBe("site"); // AAAA -> site
    expect(purposeOf("site.example.")).toBe("site"); // CNAME (not _domainkey) -> site
    expect(purposeOf('0 issue "letsencrypt.org"')).toBe("other"); // CAA -> other
    expect(purposeOf("ns1.example.")).toBe("other"); // NS -> other
    expect(purposeOf("dk.example.")).toBe("dkim"); // _domainkey CNAME -> dkim
  });

  it("NEGATIVE CONTROL: an explicit purpose on a passthrough record is respected", () => {
    // classifyPurpose only applies when purpose is unset (`rec.purpose ?? …`).
    const { records } = planFromResolvedRecords(
      [{ type: "A", host: "www", value: "1.2.3.4", ttl: 300, purpose: "verification" }],
      [],
    );
    expect(records[0]!.purpose).toBe("verification");
  });

  it("does not seed the output records or warnings with a bogus element", () => {
    // Prevents L177 `const out: DnsRecord[] = []` -> ["Stryker was here"] and L176
    // `const warnings: ConnectWarning[] = []` -> ["Stryker was here"]. A single
    // passthrough CNAME with no existing DNS yields exactly one record and no warning.
    const { records, warnings } = planFromResolvedRecords(
      [{ type: "CNAME", host: "www", value: "site.example.", ttl: 300 }],
      [],
    );
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({ type: "CNAME", host: "www", purpose: "site" });
    expect(warnings).toEqual([]);
  });
});

// ===========================================================================
// planSiteRecords — subdomain, apex-flatten, apex A/AAAA, unresolved (src L273-309).
// ===========================================================================
describe("planSiteRecords", () => {
  it("subdomain → a CNAME with the caller's TTL, purpose 'site', and no warnings", () => {
    // Prevents L280 LogicalOperator `ttl ?? 3600` -> `ttl && 3600` (a real 900 becomes
    // 3600), L280 StringLiteral `purpose: "site"` -> "", and L282 `warnings: []` ->
    // ["Stryker was here"].
    const { records, warnings } = planSiteRecords(
      { subdomain: "www", target: "pages.gbuild.app", supportsApex: false, ttl: 900 },
      [],
    );
    expect(records[0]).toMatchObject({ type: "CNAME", host: "www", value: "pages.gbuild.app.", purpose: "site" });
    expect(records[0]!.ttl).toBe(900);
    expect(warnings).toEqual([]);
  });

  it("apex on a flattening host → a CNAME at @ with the caller's TTL and purpose 'site'", () => {
    // Prevents L291 LogicalOperator `ttl ?? 3600` -> `ttl && 3600`, L291 StringLiteral
    // `purpose: "site"` -> "", and L293 `warnings: []` -> ["Stryker was here"].
    const { records, warnings } = planSiteRecords(
      { subdomain: "", target: "pages.gbuild.app", supportsApex: true, ttl: 900 },
      [],
    );
    expect(records[0]).toMatchObject({ type: "CNAME", host: "@", value: "pages.gbuild.app.", purpose: "site" });
    expect(records[0]!.ttl).toBe(900);
    expect(warnings).toEqual([]);
  });

  it("apex, non-flattening, with resolved IPs → A records at the caller's TTL, no warnings", () => {
    // Prevents the L301 ttl-spread mutants (ObjectLiteral -> {}, ConditionalExpression
    // -> false, EqualityOperator) and L304 `warnings: []` -> ["Stryker was here"].
    const { records, warnings } = planSiteRecords(
      { subdomain: "", target: "pages.gbuild.app", supportsApex: false, resolved: { a: ["1.2.3.4"] }, ttl: 900 },
      [],
    );
    expect(records[0]).toMatchObject({ type: "A", host: "@", value: "1.2.3.4" });
    expect(records[0]!.ttl).toBe(900);
    expect(warnings).toEqual([]);
  });

  it("NEGATIVE CONTROL: an omitted TTL flattens at planApex's 300 default", () => {
    // Proves the TTL above is actually plumbed through, not a coincidence of 900.
    const { records } = planSiteRecords(
      { subdomain: "", target: "pages.gbuild.app", supportsApex: false, resolved: { a: ["1.2.3.4"] } },
      [],
    );
    expect(records[0]!.ttl).toBe(300);
  });

  it("apex, non-flattening, unresolved → warns with planApex's reason, never a literal 'apex'", () => {
    // Prevents L308 ConditionalExpression -> false, EqualityOperator `!==`, and the
    // "unresolved" StringLiteral -> "" — each of which would emit the terse "apex"
    // string instead of the actionable reason. The detail must tell the caller to
    // resolve the target first.
    const { records, warnings } = planSiteRecords(
      { subdomain: "", target: "pages.gbuild.app", supportsApex: false },
      [],
    );
    expect(records).toHaveLength(0);
    const warn = warnings.find((w) => w.code === "apex_cname")!;
    expect(warn).toBeDefined();
    expect(warn.detail).toContain("Resolve the target first");
    expect(warn.detail).not.toBe("apex");
  });
});
