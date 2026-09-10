// Latch — connect() orchestrator: mutation-hardening tests.
//
// Companion to connect.test.ts. That file pins the happy paths and the P0
// guarantees; this one closes the mutants that survived it and covers the
// branches the happy-path suite never reaches — the resolvePath reason strings,
// the readCurrent authoritative-vs-DoH fork, the site / resolved-records / empty
// buildRecords branches, the Domain Connect no-config + no-redirect paths, and
// the apply()-returned-empty manual_fallback shaping.
//
// Each test says WHICH defect it prevents. Every group carries a NEGATIVE
// CONTROL (or is written so a function that always returns the positive answer
// still fails), and no test performs a real network call: connect() takes every
// external effect through injected deps, and the fake adapters below never fetch.

import { describe, expect, it } from "vitest";
import type {
  Adapter,
  AdapterApplyResult,
  AdapterAuth,
  DetectResult,
  DnsRecord,
} from "../../src/types";
import { LatchError } from "../../src/types";
import { CLOUDFLARE_CAPABILITIES } from "../../src/providers";
import { connect, type ConnectDeps } from "../../src/connect/connect";
import { V1_COVERAGE } from "../../src/connect/coverage";

function det(method: DetectResult["method"], extra: Partial<DetectResult> = {}): DetectResult {
  return {
    domain: "acme.com",
    dnsHost: null,
    method,
    confidence: 0.9,
    dnssec: false,
    registered: true,
    parked: false,
    existingMx: [],
    nameservers: [],
    ...extra,
  };
}

/** A full adapter (has readExisting). */
function fakeAdapter(opts: {
  existing?: DnsRecord[];
  throwOnRead?: Error;
  onApply?: (records: DnsRecord[]) => AdapterApplyResult;
  applyResult?: AdapterApplyResult;
  throwOnApply?: Error;
}): Adapter {
  return {
    capabilities: () => CLOUDFLARE_CAPABILITIES,
    readExisting: async () => {
      if (opts.throwOnRead) throw opts.throwOnRead;
      return opts.existing ?? [];
    },
    apply: async (_domain, records): Promise<AdapterApplyResult> => {
      if (opts.throwOnApply) throw opts.throwOnApply;
      if (opts.applyResult) return opts.applyResult;
      if (opts.onApply) return opts.onApply(records);
      return { applied: records.map((r) => ({ ...r })), manual: [] };
    },
  };
}

/** An adapter WITHOUT readExisting — a sync/manual host that cannot read the zone. */
function adapterNoRead(opts: {
  onApply?: (records: DnsRecord[]) => AdapterApplyResult;
  throwOnApply?: Error;
}): Adapter {
  return {
    capabilities: () => CLOUDFLARE_CAPABILITIES,
    apply: async (_domain, records): Promise<AdapterApplyResult> => {
      if (opts.throwOnApply) throw opts.throwOnApply;
      if (opts.onApply) return opts.onApply(records);
      return { applied: records.map((r) => ({ ...r })), manual: [] };
    },
  };
}

const OWNED = async (): Promise<AdapterAuth | null> => ({ zoneId: "z", token: "t" });

// ---------------------------------------------------------------------------
// resolvePath — the reason strings and the wiring matrix. connect.test.ts
// asserts the STATUS of these paths but not the reason detail, so the string
// literals and several guard branches survived. (src lines 91-113)
// ---------------------------------------------------------------------------
describe("resolvePath reason strings + wiring", () => {
  it("Cloudflare NS not in our account → the exact 'not in this account' reason (L91/L93)", async () => {
    // Prevents the L91 `if` collapsing (which drops through to 'no automated
    // path') and blanking the L93 reason string: the manual warning must name
    // WHY — that a CF-hosted zone we don't own can't be auto-written.
    const deps: ConnectDeps = {
      getAdapter: () => fakeAdapter({}),
      resolveOwnedCloudflareZone: async () => null,
      readExistingViaDns: async () => [],
      newJobId: () => "j",
    };
    const res = await connect(
      { detect: det("cloudflare"), email: { subdomain: "agent", spfIncludes: [] } },
      deps,
    );
    expect(res.status).toBe("manual_fallback");
    expect(res.controlProof).toBeUndefined();
    expect(res.warnings.some((w) => w.detail === "Cloudflare-hosted but not in this account")).toBe(true);
  });

  it("Domain Connect method with DC OFF (V1 default) → 'Domain Connect disabled' (L97)", async () => {
    // Prevents the L97 guard flipping to false and blanking its reason: with DC
    // off (no gbuild-email template yet), a domain_connect detection must degrade
    // to manual naming that it is DISABLED — not fall through to 'settings
    // unavailable' or an empty reason.
    const deps: ConnectDeps = {
      coverage: V1_COVERAGE, // domainConnect: false
      getAdapter: () => undefined,
      readExistingViaDns: async () => [],
      newJobId: () => "j",
    };
    const res = await connect(
      { detect: det("domain_connect"), email: { subdomain: "agent", spfIncludes: [] } },
      deps,
    );
    expect(res.status).toBe("manual_fallback");
    expect(res.warnings.some((w) => w.detail === "Domain Connect disabled")).toBe(true);
  });

  it("a manual detection → the 'no automated path' reason, not a wiring reason (L102/L113)", async () => {
    // Prevents L102 `if (id)` being forced true (which would report the null id
    // as 'null not wired in v1') and blanking the L113 reason: an unrecognized
    // host has no adapter id and must land on 'no automated path for this DNS host'.
    const res = await connect(
      { detect: det("manual"), email: { subdomain: "agent", spfIncludes: [] } },
      { getAdapter: () => undefined, readExistingViaDns: async () => [], newJobId: () => "j" },
    );
    expect(res.status).toBe("manual_fallback");
    expect(res.warnings.some((w) => w.detail === "no automated path for this DNS host")).toBe(true);
  });

  it("route53 present but NOT wired → 'route53 not wired in v1' (L103/L104)", async () => {
    // Prevents L104 `if (!wired)` flipping to false (which proceeds to a write
    // path with no registered adapter) and proves the route53 operand of the
    // wired expression is actually consulted.
    const res = await connect(
      { detect: det("adapter:route53"), email: { subdomain: "agent", spfIncludes: [] } },
      {
        coverage: { cloudflare: true, domainConnect: false, route53: false, namecheap: false },
        getAdapter: () => undefined,
        readExistingViaDns: async () => [],
        newJobId: () => "j",
      },
    );
    expect(res.status).toBe("manual_fallback");
    expect(res.warnings.some((w) => w.detail === "route53 not wired in v1")).toBe(true);
  });

  it("namecheap unwired stays manual even when the route53 flag is ON (L103 left && / ===)", async () => {
    // Prevents the LEFT `&&` becoming `||` (which would let a true route53 flag
    // wire namecheap) and the `id === "route53"` operand being forced true: a
    // namecheap detection must not borrow route53's coverage bit.
    const res = await connect(
      { detect: det("adapter:namecheap"), email: { subdomain: "agent", spfIncludes: [] } },
      {
        coverage: { cloudflare: true, domainConnect: false, route53: true, namecheap: false },
        getAdapter: () => undefined,
        readExistingViaDns: async () => [],
        newJobId: () => "j",
      },
    );
    expect(res.status).toBe("manual_fallback");
    expect(res.warnings.some((w) => w.detail === "namecheap not wired in v1")).toBe(true);
  });

  it("route53 unwired stays manual even when the namecheap flag is ON (L103 right && / !==)", async () => {
    // Prevents the RIGHT `&&` becoming `||`, the `id === "namecheap"` operand
    // flipping to `!==` or being forced true (each would let a true namecheap
    // flag wire route53): route53 must read only its own coverage bit.
    const res = await connect(
      { detect: det("adapter:route53"), email: { subdomain: "agent", spfIncludes: [] } },
      {
        coverage: { cloudflare: true, domainConnect: false, route53: false, namecheap: true },
        getAdapter: () => undefined,
        readExistingViaDns: async () => [],
        newJobId: () => "j",
      },
    );
    expect(res.status).toBe("manual_fallback");
    expect(res.warnings.some((w) => w.detail === "route53 not wired in v1")).toBe(true);
  });

  it("namecheap WIRED → writes via its adapter with user_credentials proof (L103 string literal)", async () => {
    // Positive control + prevents the `"namecheap"` literal being blanked (which
    // would make a genuinely-wired namecheap fall to manual).
    const nc = fakeAdapter({});
    const res = await connect(
      { detect: det("adapter:namecheap"), email: { subdomain: "agent", spfIncludes: [] } },
      {
        coverage: { cloudflare: true, domainConnect: false, route53: true, namecheap: true },
        getAdapter: (id) => (id === "namecheap" ? nc : undefined),
        adapterAuth: (id) => (id === "namecheap" ? { apiUser: "u", apiKey: "k" } : undefined),
        readExistingViaDns: async () => [],
        newJobId: () => "j",
      },
    );
    expect(res.status).toBe("applied");
    expect(res.controlProof).toEqual({ kind: "user_credentials" });
  });

  it("route53 WIRED → writes via its adapter with user_credentials proof (L103 string literal)", async () => {
    // Positive control for the route53 operand's string literal.
    const r53 = fakeAdapter({});
    const res = await connect(
      { detect: det("adapter:route53"), email: { subdomain: "agent", spfIncludes: [] } },
      {
        getAdapter: (id) => (id === "route53" ? r53 : undefined),
        adapterAuth: (id) => (id === "route53" ? { accessKeyId: "a", secretAccessKey: "b" } : undefined),
        readExistingViaDns: async () => [],
        newJobId: () => "j",
      },
    );
    expect(res.status).toBe("applied");
    expect(res.controlProof).toEqual({ kind: "user_credentials" });
  });

  it("adapterAuth is OPTIONAL — a wired adapter still writes when no creds resolver is given (L108)", async () => {
    // Prevents dropping the optional chaining on `deps.adapterAuth?.(id)`:
    // without it, an absent adapterAuth resolver throws a TypeError from
    // resolvePath and connect() rejects instead of writing with undefined auth.
    const r53 = fakeAdapter({});
    const res = await connect(
      { detect: det("adapter:route53"), email: { subdomain: "agent", spfIncludes: [] } },
      {
        // no adapterAuth provided
        getAdapter: (id) => (id === "route53" ? r53 : undefined),
        readExistingViaDns: async () => [],
        newJobId: () => "j",
      },
    );
    expect(res.status).toBe("applied");
  });
});

// ---------------------------------------------------------------------------
// readCurrent — the authoritative-adapter-read vs best-effort-DoH fork, and the
// three-way viaAdapter outcome (records / "no-method" / "failed"). The write
// paths in connect.test.ts always used a readable adapter, so the no-method and
// no-DoH branches were entirely uncovered. (src lines 131-161)
// ---------------------------------------------------------------------------
describe("readCurrent — authoritative read vs DoH fallback", () => {
  it("reads authoritatively THROUGH the route53 adapter, not via DoH (L106/L145/L146)", async () => {
    // Prevents: the path kind literal "adapter" being blanked (L106), the L145
    // branch that gates the authoritative read flipping, and L146 forcing the
    // id to "cloudflare". If any fires, the merge would run against the DoH view
    // instead of the adapter's — so we seed DIFFERENT records in each and assert
    // the adapter's (google) won, not DoH's (a decoy include).
    const r53 = fakeAdapter({
      existing: [{ type: "TXT", host: "agent", value: "v=spf1 include:_spf.google.com ~all", ttl: 3600 }],
    });
    const deps: ConnectDeps = {
      getAdapter: (id) => (id === "route53" ? r53 : undefined),
      adapterAuth: (id) => (id === "route53" ? { accessKeyId: "a", secretAccessKey: "b" } : undefined),
      readExistingViaDns: async () => [
        { type: "TXT", host: "agent", value: "v=spf1 include:_spf.decoy.example ~all", ttl: 3600 },
      ],
      newJobId: () => "j",
    };
    const res = await connect(
      { detect: det("adapter:route53"), email: { subdomain: "agent", spfIncludes: ["include:_spf.resend.com"] } },
      deps,
    );
    const spf = res.applied.find((r) => r.purpose === "spf")!;
    expect(spf.value).toBe("v=spf1 include:_spf.google.com include:_spf.resend.com ~all");
    expect(spf.value).not.toContain("decoy");
  });

  it("cloudflare authoritative read wins over DoH (L145 conditional/string)", async () => {
    // Same guarantee for the cloudflare write path: the CF-API read-back must
    // seed the merge, never the stale DoH cache.
    const cf = fakeAdapter({
      existing: [{ type: "TXT", host: "agent", value: "v=spf1 include:_spf.google.com ~all", ttl: 3600 }],
    });
    const deps: ConnectDeps = {
      getAdapter: (id) => (id === "cloudflare" ? cf : undefined),
      resolveOwnedCloudflareZone: OWNED,
      readExistingViaDns: async () => [
        { type: "TXT", host: "agent", value: "v=spf1 include:_spf.decoy.example ~all", ttl: 3600 },
      ],
      newJobId: () => "j",
    };
    const res = await connect(
      { detect: det("cloudflare"), email: { subdomain: "agent", spfIncludes: ["include:_spf.resend.com"] } },
      deps,
    );
    const spf = res.applied.find((r) => r.purpose === "spf")!;
    expect(spf.value).toBe("v=spf1 include:_spf.google.com include:_spf.resend.com ~all");
    expect(spf.value).not.toContain("decoy");
  });

  it("adapter with NO readExisting → falls to DoH, still writes (L137/L149/L153-160)", async () => {
    // A write-path adapter that cannot read the zone must return "no-method" and
    // fall to best-effort DoH — NOT return the "no-method" sentinel as records
    // (L149) nor throw for a missing readExisting (L137). DoH seeds the merge.
    const cf = adapterNoRead({});
    const deps: ConnectDeps = {
      getAdapter: (id) => (id === "cloudflare" ? cf : undefined),
      resolveOwnedCloudflareZone: OWNED,
      readExistingViaDns: async () => [
        { type: "TXT", host: "agent", value: "v=spf1 include:_spf.google.com ~all", ttl: 3600 },
      ],
      newJobId: () => "j",
    };
    const res = await connect(
      { detect: det("cloudflare"), email: { subdomain: "agent", spfIncludes: ["include:_spf.resend.com"] } },
      deps,
    );
    expect(res.status).toBe("applied");
    const spf = res.applied.find((r) => r.purpose === "spf")!;
    expect(spf.value).toBe("v=spf1 include:_spf.google.com include:_spf.resend.com ~all");
  });

  it("write path with NO authoritative read AND no DoH → writes against an empty zone (L153/L160)", async () => {
    // Reaches the final `return { records: [], authoritativeFailed: false }`
    // with a write path. Prevents: L160 turning that into {} (undefined records
    // crash the plan), into authoritativeFailed:true (would wrongly degrade to
    // manual), or into a bogus records array (a DKIM template forces the typesAt
    // guard to touch each element). Also prevents L153 being forced to CALL an
    // absent readExistingViaDns.
    const cf = adapterNoRead({});
    const deps: ConnectDeps = {
      getAdapter: (id) => (id === "cloudflare" ? cf : undefined),
      resolveOwnedCloudflareZone: OWNED,
      // no readExistingViaDns
      newJobId: () => "j",
    };
    const res = await connect(
      {
        detect: det("cloudflare"),
        email: {
          subdomain: "agent",
          spfIncludes: ["include:_spf.resend.com"],
          dkim: [{ selector: "resend", recordType: "CNAME", value: "x._domainkey.example.net", ttl: 3600 }],
        },
      },
      deps,
    );
    expect(res.status).toBe("applied");
    expect(res.controlProof).toEqual({ kind: "cf_account_owned" });
  });

  it("DoH read that THROWS is swallowed — the write still proceeds (L156/L157)", async () => {
    // Reaches the DoH catch on a WRITE path (adapter can't read → DoH → throws).
    // Prevents emptying the catch block (L156, which loses the return), and the
    // L157 mutants: {} (undefined records), authoritativeFailed:true (would
    // degrade to manual), and a bogus records array (DKIM forces typesAt).
    const cf = adapterNoRead({});
    const deps: ConnectDeps = {
      getAdapter: (id) => (id === "cloudflare" ? cf : undefined),
      resolveOwnedCloudflareZone: OWNED,
      readExistingViaDns: async () => {
        throw new Error("DoH resolver unavailable");
      },
      newJobId: () => "j",
    };
    const res = await connect(
      {
        detect: det("cloudflare"),
        email: {
          subdomain: "agent",
          spfIncludes: ["include:_spf.resend.com"],
          dkim: [{ selector: "resend", recordType: "CNAME", value: "x._domainkey.example.net", ttl: 3600 }],
        },
      },
      deps,
    );
    expect(res.status).toBe("applied");
    expect(res.controlProof).toEqual({ kind: "cf_account_owned" });
  });

  it("manual path merges the DoH-read existing SPF (L153 false / L153-154 blocks)", async () => {
    // On the manual path a DoH read is the best-effort existing source. Prevents
    // L153 being forced false or its (and the try) block being emptied — either
    // would discard the DoH result and skip the SPF merge.
    const deps: ConnectDeps = {
      getAdapter: () => undefined,
      readExistingViaDns: async () => [
        { type: "TXT", host: "agent", value: "v=spf1 include:_spf.google.com ~all", ttl: 3600 },
      ],
      newJobId: () => "j",
    };
    const res = await connect(
      { detect: det("manual"), email: { subdomain: "agent", spfIncludes: ["include:_spf.resend.com"] } },
      deps,
    );
    expect(res.status).toBe("manual_fallback");
    const spf = res.manual.find((r) => r.purpose === "spf")!;
    expect(spf.value).toBe("v=spf1 include:_spf.google.com include:_spf.resend.com ~all");
  });

  it("manual path with NO DoH reader → still returns the prepared records (L160)", async () => {
    // Reaches the final empty-read return on a NON-write path. Prevents L160
    // becoming {} (undefined existing crashes the plan) and confirms a missing
    // DoH reader is not fatal.
    const res = await connect(
      { detect: det("manual"), email: { subdomain: "agent", spfIncludes: ["include:_spf.resend.com"] } },
      { getAdapter: () => undefined, newJobId: () => "j" },
    );
    expect(res.status).toBe("manual_fallback");
    expect(res.manual.some((r) => r.purpose === "spf")).toBe(true);
  });

  it("NEGATIVE CONTROL: a readable adapter that returns [] does NOT crash and writes (L145/L148)", async () => {
    // If readCurrent always returned garbage records, the merge tests above could
    // pass vacuously. A clean empty authoritative read must produce a clean write.
    const cf = fakeAdapter({ existing: [] });
    const res = await connect(
      { detect: det("cloudflare"), email: { subdomain: "agent", spfIncludes: ["include:_spf.resend.com"] } },
      { getAdapter: (id) => (id === "cloudflare" ? cf : undefined), resolveOwnedCloudflareZone: OWNED, newJobId: () => "j" },
    );
    expect(res.status).toBe("applied");
    const spf = res.applied.find((r) => r.purpose === "spf")!;
    expect(spf.value).toBe("v=spf1 include:_spf.resend.com ~all");
  });
});

// ---------------------------------------------------------------------------
// authoritativeFailed — a write path whose authoritative read THREW must not
// write blind. connect.test.ts asserts the status; this adds the reason strings
// and a DKIM template so the "records:[]" used on failure is actually consulted.
// (src lines 148, 208-222)
// ---------------------------------------------------------------------------
describe("authoritative read failure → manual, with its reasons", () => {
  it("degrades to manual naming the failure, using an EMPTY existing set (L148/L217/L220)", async () => {
    // Prevents: L148 seeding a bogus records array on failure (the DKIM template
    // forces typesAt to read each element — a string element would crash), L217
    // blanking the 'could not read ... merge safely' provider_error detail, and
    // L220 blanking the 'authoritative read failed' manual_fallback reason.
    const cf = fakeAdapter({ throwOnRead: new LatchError("provider_rejected", "transient read failure") });
    const deps: ConnectDeps = {
      getAdapter: (id) => (id === "cloudflare" ? cf : undefined),
      resolveOwnedCloudflareZone: OWNED,
      readExistingViaDns: async () => [],
      newJobId: () => "j",
    };
    const res = await connect(
      {
        detect: det("cloudflare"),
        email: {
          subdomain: "agent",
          spfIncludes: ["include:_spf.resend.com"],
          dkim: [{ selector: "resend", recordType: "CNAME", value: "x._domainkey.example.net", ttl: 3600 }],
        },
      },
      deps,
    );
    expect(res.status).toBe("manual_fallback");
    expect(res.applied).toHaveLength(0); // apply must never have run
    expect(
      res.warnings.some(
        (w) => w.code === "provider_error" && w.detail.includes("merge safely"),
      ),
    ).toBe(true);
    expect(
      res.warnings.some(
        (w) => w.code === "manual_fallback" && w.detail === "authoritative read failed",
      ),
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// buildRecords — the site / resolved-records / empty branches were entirely
// uncovered (connect.test.ts only ever passed email). (src lines 163-169)
// ---------------------------------------------------------------------------
describe("buildRecords branch selection", () => {
  it("a site plan produces the site CNAME (L165)", async () => {
    // Prevents L165 flipping: forced false drops the site branch (empty plan),
    // forced true would take it for a records-only input (crash on undefined).
    const cf = fakeAdapter({ existing: [] });
    const res = await connect(
      {
        detect: det("cloudflare"),
        site: { subdomain: "www", target: "pages.example.dev", supportsApex: false },
      },
      { getAdapter: (id) => (id === "cloudflare" ? cf : undefined), resolveOwnedCloudflareZone: OWNED, newJobId: () => "j" },
    );
    expect(res.status).toBe("applied");
    expect(res.applied.some((r) => r.type === "CNAME" && r.host === "www")).toBe(true);
  });

  it("a caller-supplied resolved record set is classified and written (L168)", async () => {
    // Prevents L168 flipping: forced false drops the records branch (empty plan),
    // forced true would take it for email/site inputs.
    const cf = fakeAdapter({ existing: [] });
    const res = await connect(
      {
        detect: det("cloudflare"),
        records: [{ type: "A", host: "@", value: "203.0.113.7", ttl: 300 }],
      },
      { getAdapter: (id) => (id === "cloudflare" ? cf : undefined), resolveOwnedCloudflareZone: OWNED, newJobId: () => "j" },
    );
    expect(res.status).toBe("applied");
    expect(res.applied.some((r) => r.type === "A" && r.host === "@" && r.value === "203.0.113.7")).toBe(true);
  });

  it("an input with NO email/site/records → an empty, warning-free plan (L164/165/168 true, L169)", async () => {
    // Reaches the final `return { records: [], warnings: [] }`. Forcing any of
    // the three branch guards true would call a plan fn with undefined (crash);
    // L169 becoming {} (undefined warnings crash the spread) or a bogus array
    // (records → a spurious "applied"; warnings → a spurious warning) is caught
    // by asserting an empty applied set and zero warnings.
    const cf = fakeAdapter({ existing: [] });
    const res = await connect(
      { detect: det("cloudflare") },
      { getAdapter: (id) => (id === "cloudflare" ? cf : undefined), resolveOwnedCloudflareZone: OWNED, newJobId: () => "j" },
    );
    expect(res.status).toBe("manual_fallback"); // nothing applied → fallback
    expect(res.applied).toHaveLength(0);
    expect(res.warnings).toHaveLength(0);
  });

  it("propagates a plan warning into the result (L197)", async () => {
    // Prevents L197 replacing `[...plan.warnings]` with `[]`: a clobber-guard
    // warning raised while planning (existing MX at the identity host) must
    // survive into the connect() result.
    const cf = fakeAdapter({
      existing: [{ type: "MX", host: "agent", value: "incumbent.mail.example.net", ttl: 3600, priority: 10 }],
    });
    const res = await connect(
      {
        detect: det("cloudflare"),
        email: {
          subdomain: "agent",
          spfIncludes: [],
          mx: [{ priority: 10, target: "new-mx.example.net" }],
        },
      },
      { getAdapter: (id) => (id === "cloudflare" ? cf : undefined), resolveOwnedCloudflareZone: OWNED, newJobId: () => "j" },
    );
    expect(res.warnings.some((w) => w.code === "existing_mx")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Domain Connect path — connect.test.ts covered the happy oauth_required case;
// the no-config, no-redirect, and result-shape details survived. (src 226-245)
// ---------------------------------------------------------------------------
describe("Domain Connect path", () => {
  const dcDeps = (over: Partial<ConnectDeps>): ConnectDeps => ({
    coverage: { cloudflare: true, domainConnect: true, route53: true, namecheap: false },
    getAdapter: () => undefined,
    readExistingViaDns: async () => [],
    newJobId: () => "j",
    ...over,
  });

  it("oauth_required carries empty applied/manual and no stray redirect literal (L230/L235/L236)", async () => {
    // Prevents L235/L236 seeding the applied/manual arrays with a marker, and
    // L230 turning the default redirect "" into a marker string. No redirectUri
    // is supplied, so the URL's redirect_uri must be empty, not a mutant literal.
    const res = await connect(
      { detect: det("domain_connect"), email: { subdomain: "agent", spfIncludes: [] } },
      dcDeps({
        domainConnectConfig: () => ({
          providerId: "GoDaddy",
          serviceId: "gbuild-email",
          urlSyncUX: "https://dc.godaddy.com/sync",
        }),
      }),
    );
    expect(res.status).toBe("oauth_required");
    expect(res.applied).toHaveLength(0);
    expect(res.manual).toHaveLength(0);
    expect(res.authUrl).toContain("/services/gbuild-email/apply");
    expect(res.authUrl).toContain("redirect_uri=");
    expect(res.authUrl).not.toContain("Stryker");
  });

  it("no domainConnectConfig resolver → manual 'settings unavailable' (L227/L245)", async () => {
    // Prevents dropping the optional chaining on `deps.domainConnectConfig?.(…)`
    // (L227: an absent resolver would throw a TypeError instead of degrading)
    // and blanking the L245 reason.
    const res = await connect(
      { detect: det("domain_connect"), email: { subdomain: "agent", spfIncludes: [] } },
      dcDeps({}), // no domainConnectConfig
    );
    expect(res.status).toBe("manual_fallback");
    expect(res.warnings.some((w) => w.detail === "Domain Connect settings unavailable")).toBe(true);
  });

  it("a null domainConnectConfig → manual 'settings unavailable' (behavior for L228/L231)", async () => {
    // The config-null path (behavioral coverage for the L228/L231 conditionals,
    // documented as equivalent in the report): a null config never builds a URL.
    const res = await connect(
      { detect: det("domain_connect"), email: { subdomain: "agent", spfIncludes: [] } },
      dcDeps({ domainConnectConfig: () => null }),
    );
    expect(res.status).toBe("manual_fallback");
    expect(res.warnings.some((w) => w.detail === "Domain Connect settings unavailable")).toBe(true);
  });

  it("does NOT do an authoritative adapter read for a consent path (L145 → true)", async () => {
    // A domain_connect path must not touch getAdapter for a zone read — that is
    // only for cloudflare/adapter write paths. Prevents L145's guard being forced
    // true: with a getAdapter that returns a throwing-read adapter for ANY id, a
    // forced adapter read would flag authoritativeFailed and wrongly degrade to
    // manual instead of returning oauth_required.
    const throwingRead: Adapter = {
      capabilities: () => CLOUDFLARE_CAPABILITIES,
      readExisting: async () => {
        throw new Error("read should never be attempted on a consent path");
      },
      apply: async () => ({ applied: [], manual: [] }),
    };
    const res = await connect(
      { detect: det("domain_connect"), email: { subdomain: "agent", spfIncludes: [] } },
      dcDeps({
        getAdapter: () => throwingRead,
        redirectUri: "gbuild://cb",
        domainConnectConfig: () => ({
          providerId: "GoDaddy",
          serviceId: "gbuild-email",
          urlSyncUX: "https://dc.godaddy.com/sync",
        }),
      }),
    );
    expect(res.status).toBe("oauth_required");
  });
});

// ---------------------------------------------------------------------------
// Write dispatch — no-adapter guard, apply()-returned-empty shaping, and the
// non-LatchError catch detail. (src lines 252-280)
// ---------------------------------------------------------------------------
describe("write dispatch + manual_fallback shaping", () => {
  it("a wired path with no REGISTERED adapter → 'no adapter registered' (L252/L253)", async () => {
    // Prevents L252's guard flipping/emptying (which would call apply on
    // undefined and surface a generic 'provider write failed') and L253 blanking
    // the reason. resolvePath wires route53; getAdapter returns nothing for it.
    const res = await connect(
      { detect: det("adapter:route53"), email: { subdomain: "agent", spfIncludes: [] } },
      {
        getAdapter: () => undefined,
        adapterAuth: () => ({ accessKeyId: "a", secretAccessKey: "b" }),
        readExistingViaDns: async () => [],
        newJobId: () => "j",
      },
    );
    expect(res.status).toBe("manual_fallback");
    expect(res.warnings.some((w) => w.detail === "no adapter registered for route53")).toBe(true);
  });

  it("apply() returns applied:[] with NO manual → manual_fallback carries the planned records (L258/L259/L261/L263)", async () => {
    // The provider accepted the call but wrote nothing. Prevents: L258 flipping
    // (would report status 'applied' with an empty applied set), L259/L261
    // blanking the result / status literal, and the L263 ternary — forced true
    // or `>=0` yields the adapter's empty manual; the arrow→undefined / {}
    // mutants yield element-less records. So the fallback must surface the
    // PLANNED records with real fields.
    const cf = fakeAdapter({ existing: [], applyResult: { applied: [], manual: [] } });
    const res = await connect(
      { detect: det("cloudflare"), email: { subdomain: "agent", spfIncludes: ["include:_spf.resend.com"] } },
      { getAdapter: (id) => (id === "cloudflare" ? cf : undefined), resolveOwnedCloudflareZone: OWNED, newJobId: () => "j" },
    );
    expect(res.status).toBe("manual_fallback");
    expect(res.manual.some((r) => r?.purpose === "spf" && r.value.includes("resend"))).toBe(true);
  });

  it("apply() returns applied:[] WITH a provider manual set → that set is surfaced verbatim (L263 false / <=0)", async () => {
    // The other half of the L263 ternary: when the adapter DID return a manual
    // set, it must be used as-is — not overwritten by the planned records. A
    // forced-false or `<=0` mutant would discard the adapter's custom record.
    const cf = fakeAdapter({
      existing: [],
      applyResult: {
        applied: [],
        manual: [{ type: "TXT", host: "custom", value: "provider-supplied", ttl: 300, note: "add me" }],
      },
    });
    const res = await connect(
      { detect: det("cloudflare"), email: { subdomain: "agent", spfIncludes: ["include:_spf.resend.com"] } },
      { getAdapter: (id) => (id === "cloudflare" ? cf : undefined), resolveOwnedCloudflareZone: OWNED, newJobId: () => "j" },
    );
    expect(res.status).toBe("manual_fallback");
    expect(res.manual.some((r) => r.host === "custom" && r.value === "provider-supplied")).toBe(true);
    // NEGATIVE CONTROL: the planned SPF must NOT be present — the adapter's set won.
    expect(res.manual.some((r) => r.purpose === "spf")).toBe(false);
  });

  it("a non-LatchError thrown by apply() → the generic 'provider write failed' detail (L272)", async () => {
    // connect.test.ts throws a LatchError (detail = its message). Prevents L272
    // blanking the fallback detail used for a plain Error.
    const cf = fakeAdapter({ existing: [], throwOnApply: new Error("socket hang up") });
    const res = await connect(
      { detect: det("cloudflare"), email: { subdomain: "agent", spfIncludes: [] } },
      { getAdapter: (id) => (id === "cloudflare" ? cf : undefined), resolveOwnedCloudflareZone: OWNED, newJobId: () => "j" },
    );
    expect(res.status).toBe("manual_fallback");
    expect(
      res.warnings.some((w) => w.code === "provider_error" && w.detail === "provider write failed"),
    ).toBe(true);
  });

  it("NEGATIVE CONTROL: apply() that returns a real applied set → status 'applied' (guards L258/L263)", async () => {
    // Proves the manual_fallback shaping above is reached only when applied is
    // empty — a normal write must report 'applied', not fallback.
    const cf = fakeAdapter({ existing: [] });
    const res = await connect(
      { detect: det("cloudflare"), email: { subdomain: "agent", spfIncludes: ["include:_spf.resend.com"] } },
      { getAdapter: (id) => (id === "cloudflare" ? cf : undefined), resolveOwnedCloudflareZone: OWNED, newJobId: () => "j" },
    );
    expect(res.status).toBe("applied");
    expect(res.applied.length).toBeGreaterThan(0);
  });
});
