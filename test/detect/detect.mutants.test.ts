import { describe, it, expect } from "vitest";
import { detect } from "../../src/detect/detect";
import type { SettingsFetcher } from "../../src/detect/domain-connect";
import type {
  Resolver,
  DnsResponse,
  DnsAnswer,
  DnsQueryType,
  QueryOptions,
} from "../../src/net/resolver";

// Mutation-closing tests for src/detect/detect.ts.
//
// The existing test/detect/detect.test.ts drives the provider matrix and the
// four DNSSEC signals. This file pins the parts a mutation run left open:
// input normalization observed at the QUERY (not just the result), rr-type
// filtering, the base-result defaults visible on the early-return paths, the
// confidence values that distinguish those paths, the resolver-throws
// degradation, the DNSSEC `do`-flag on the DS/DNSKEY queries, the
// attemptDomainConnect gate in both directions, the "no fetchSettings means no
// probe" invariant, and the manual-treatment tail of chooseMethod().
//
// No network: every resolver here is a fake with canned answers, matching the
// existing suite's approach.

const RR = {
  A: 1,
  MX: 15,
  TXT: 16,
  NS: 2,
  DS: 43,
  DNSKEY: 48,
} as const;

interface RecordedQuery {
  name: string;
  type: DnsQueryType;
  opts?: QueryOptions;
}

/**
 * Fake resolver: canned responses keyed "<name>|<TYPE>", records every query
 * (name, type, opts) for observation, and can be told to throw for a chosen set
 * of query types so the safe-degradation paths can be exercised without network.
 */
class FakeResolver implements Resolver {
  private readonly map: Map<string, DnsResponse>;
  readonly seen: string[] = [];
  readonly queries: RecordedQuery[] = [];

  constructor(
    entries: Array<[string, DnsResponse]>,
    private readonly throwOnTypes: ReadonlySet<DnsQueryType> = new Set(),
  ) {
    this.map = new Map(entries);
  }

  async query(name: string, type: DnsQueryType, opts?: QueryOptions): Promise<DnsResponse> {
    this.seen.push(`${name}|${type}`);
    this.queries.push({ name, type, opts });
    if (this.throwOnTypes.has(type)) {
      throw new Error(`simulated resolver failure for ${type} ${name}`);
    }
    return this.map.get(`${name}|${type}`) ?? { Status: 0, Answer: [] };
  }
}

function ns(name: string, hosts: string[]): [string, DnsResponse] {
  return [
    `${name}|NS`,
    { Status: 0, Answer: hosts.map((h) => ({ name, type: RR.NS, TTL: 3600, data: h })) },
  ];
}

function raw(name: string, type: DnsQueryType, answers: DnsAnswer[]): [string, DnsResponse] {
  return [`${name}|${type}`, { Status: 0, Answer: answers }];
}

function txt(name: string, values: string[]): [string, DnsResponse] {
  return [
    `${name}|TXT`,
    { Status: 0, Answer: values.map((v) => ({ name, type: RR.TXT, TTL: 3600, data: `"${v}"` })) },
  ];
}

const settingsFor =
  (doc: Record<string, unknown> | null): SettingsFetcher =>
  async () =>
    doc as never;

const CF = ["aida.ns.cloudflare.com."];

describe("detect() — input normalization", () => {
  it("queries the normalized zone, not the raw input", () => {
    // Prevents dropping normalizeDomain (L44 MethodExpression): the resolver must
    // be asked for "acme.com", never "ACME.com.". Asserting the query name (rather
    // than only result.domain) pins the normalization at the point it matters —
    // the wire lookup key.
    const r = new FakeResolver([ns("acme.com", CF)]);
    return detect("ACME.com.", r).then(() => {
      expect(r.seen[0]).toBe("acme.com|NS");
    });
  });
});

describe("detect() — existing MX extraction", () => {
  it("keeps only MX answers and strips the priority token", async () => {
    // Prevents dropping the rr-type filter (L48 MethodExpression / Conditional):
    // a stray A record in the MX response must not be read as a mail target. Also
    // prevents dropping mxTarget's trim().split() (L53 MethodExpression): without
    // it the whole "10 mail…" string is consumed and the target is lost.
    const r = new FakeResolver([
      ns("mailer.com", CF),
      raw("mailer.com", "MX", [
        { name: "mailer.com", type: RR.MX, TTL: 3600, data: "10 mail.mailer.com." },
        { name: "mailer.com", type: RR.A, TTL: 3600, data: "203.0.113.9" },
      ]),
    ]);
    const res = await detect("mailer.com", r);
    expect(res.existingMx).toEqual(["mail.mailer.com"]);
  });

  it("drops a null-MX target while keeping a real one", async () => {
    // Prevents forcing the target filter true (L121 ConditionalExpression): the
    // null-MX "0 ." normalizes to "" and must be excluded, leaving only the real MX.
    const r = new FakeResolver([
      ns("mixed.com", CF),
      raw("mixed.com", "MX", [
        { name: "mixed.com", type: RR.MX, TTL: 3600, data: "0 ." },
        { name: "mixed.com", type: RR.MX, TTL: 3600, data: "10 real.mixed.com." },
      ]),
    ]);
    const res = await detect("mixed.com", r);
    expect(res.existingMx).toEqual(["real.mixed.com"]);
  });

  it("drops a doubled-root-dot target (the `!== \".\"` clause)", async () => {
    // Prevents mutating `t !== "."` to `t !== ""` (L121 StringLiteral). A single
    // "." normalizes to "" and is caught by the length check, so the "." clause
    // only bites a doubled trailing dot: "0 .." normalizes to "." and must still
    // be excluded. This is the one input that exercises that clause.
    const r = new FakeResolver([
      ns("dd.com", CF),
      raw("dd.com", "MX", [{ name: "dd.com", type: RR.MX, TTL: 3600, data: "0 .." }]),
    ]);
    const res = await detect("dd.com", r);
    expect(res.existingMx).toEqual([]);
  });
});

describe("detect() — base-result defaults on early-return paths", () => {
  it("NXDOMAIN carries dnssec:false, empty MX, and confidence 0.9", async () => {
    // Pins the base-result defaults that a delegated path would overwrite but the
    // NXDOMAIN path returns straight through: dnssec:false (L77 BooleanLiteral) and
    // existingMx:[] (L80 ArrayDeclaration). Also pins the NXDOMAIN branch itself
    // (L96 Conditional/Block): dropping it drops confidence from 0.9 to the 0.4
    // no-delegation value.
    const r = new FakeResolver([["nope.test|NS", { Status: 3, Answer: [] }]]);
    const res = await detect("nope.test", r);
    expect(res.registered).toBe(false);
    expect(res.dnssec).toBe(false);
    expect(res.existingMx).toEqual([]);
    expect(res.confidence).toBe(0.9);
  });

  it("registered-but-not-delegated returns confidence 0.4", async () => {
    // Prevents dropping the `nameservers.length === 0` early return (L107
    // Conditional/Block): without it the flow proceeds to chooseMethod(null) and
    // returns the 0.3 unknown-host value instead of the 0.4 no-delegation value.
    const r = new FakeResolver([["orphan.test|NS", { Status: 0, Answer: [] }]]);
    const res = await detect("orphan.test", r);
    expect(res.registered).toBe(true);
    expect(res.method).toBe("manual");
    expect(res.confidence).toBe(0.4);
  });

  it("a live delegated zone reports parked:false", async () => {
    // Prevents flipping the base-result parked default to true (L79 BooleanLiteral):
    // a non-parking provider leaves parked untouched, so it must read false.
    const r = new FakeResolver([ns("acme.com", CF)]);
    const res = await detect("acme.com", r);
    expect(res.parked).toBe(false);
  });
});

describe("detect() — resolver failures degrade safely (no network)", () => {
  it("an NS-query failure yields registered:false with empty nameservers", async () => {
    // Pins the else-branch of the nameserver derivation (L103 ArrayDeclaration ->
    // must be []) and the registered fallback (L105 BooleanLiteral -> must be
    // false; L105 Conditional -> must not dereference a null response).
    const r = new FakeResolver([], new Set<DnsQueryType>(["NS"]));
    const res = await detect("down.test", r);
    expect(res.registered).toBe(false);
    expect(res.nameservers).toEqual([]);
    expect(res.method).toBe("manual");
  });

  it("an MX-query failure leaves existingMx empty rather than throwing", async () => {
    // Prevents forcing `if (mxResp)` true (L118): a failed MX query returns null,
    // and dereferencing it (answersOfType) would throw. The empty result must survive.
    const r = new FakeResolver([ns("cf.com", CF)], new Set<DnsQueryType>(["MX"]));
    const res = await detect("cf.com", r);
    expect(res.existingMx).toEqual([]);
    expect(res.method).toBe("cloudflare");
  });

  it("a DS-query failure still resolves DNSSEC without throwing", async () => {
    // Prevents forcing `if (ds)` true (L156): a failed DS query returns null, and
    // reading ds.AD would throw. Detection must fall through to the DNSKEY probe
    // and report an honest false.
    const r = new FakeResolver([ns("cf.com", CF)], new Set<DnsQueryType>(["DS"]));
    const res = await detect("cf.com", r);
    expect(res.dnssec).toBe(false);
  });
});

describe("detect() — DNSSEC queries request validation", () => {
  it("sends the dnssec flag on both the DS and DNSKEY queries", async () => {
    // Prevents blanking the query options (L155/L160 ObjectLiteral -> {}) and
    // flipping the dnssec flag (L155/L160 BooleanLiteral -> false): the resolver
    // must be asked to validate, which is the whole point of the DS/DNSKEY probes.
    const r = new FakeResolver([ns("cf.com", CF)]);
    await detect("cf.com", r);
    const dsq = r.queries.find((q) => q.type === "DS");
    const dkq = r.queries.find((q) => q.type === "DNSKEY");
    expect(dsq?.opts?.dnssec).toBe(true);
    expect(dkq?.opts?.dnssec).toBe(true);
  });
});

describe("detect() — Domain Connect gating", () => {
  const godaddy = ["ns01.domaincontrol.com."];

  it("attemptDomainConnect:false skips discovery even with fetchSettings present", async () => {
    // Prevents dropping the `=== false` guard (L171 Conditional): with the guard
    // gone, discovery would run and upgrade the method to domain_connect despite
    // the caller opting out.
    const r = new FakeResolver([
      ns("shop.com", godaddy),
      txt("_domainconnect.shop.com", ["domainconnect.godaddy.com"]),
    ]);
    const res = await detect("shop.com", r, {
      attemptDomainConnect: false,
      fetchSettings: settingsFor({ providerName: "GoDaddy", urlSyncUX: "https://x/sync" }),
    });
    expect(res.method).toBe("manual");
  });

  it("attemptDomainConnect:true keeps discovery on (guard is === false, not === true)", async () => {
    // Prevents flipping the guard to `=== true` (L171 BooleanLiteral), which would
    // suppress discovery in exactly the case the caller asked for it.
    const r = new FakeResolver([
      ns("shop.com", godaddy),
      txt("_domainconnect.shop.com", ["domainconnect.godaddy.com"]),
    ]);
    const res = await detect("shop.com", r, {
      attemptDomainConnect: true,
      fetchSettings: settingsFor({ providerName: "GoDaddy", urlSyncUX: "https://x/sync" }),
    });
    expect(res.method).toBe("domain_connect");
  });

  it("does NOT probe _domainconnect when no fetchSettings is supplied", async () => {
    // Prevents dropping the `!opts.fetchSettings` guard (L172 Conditional). With
    // no settings fetcher there is nothing discovery can do, so it must not spend
    // a DNS lookup on the _domainconnect TXT at all. Observed via the query log.
    const r = new FakeResolver([
      ns("shop.com", godaddy),
      txt("_domainconnect.shop.com", ["domainconnect.godaddy.com"]),
    ]);
    await detect("shop.com", r); // no fetchSettings
    expect(r.seen).not.toContain("_domainconnect.shop.com|TXT");
  });
});

describe("detect() — treatment-based method tail", () => {
  it("a recognized Domain-Connect host with no live discovery is manual at 0.75", async () => {
    // Prevents mutating the `case \"domain_connect\"` label (L194 Conditional /
    // StringLiteral): a GoDaddy zone with no settings fetcher must land on the
    // 0.75 confidence of the domain_connect case, not the 0.8 of the manual/default
    // case it would fall into if the label were changed.
    const r = new FakeResolver([ns("shop.com", ["ns01.domaincontrol.com."])]);
    const res = await detect("shop.com", r);
    expect(res.method).toBe("manual");
    expect(res.confidence).toBe(0.75);
  });

  it("a recognized manual host is manual at 0.8 and still named", async () => {
    // Covers and pins the manual/default return (L202 ObjectLiteral -> must be a
    // real object; StringLiteral -> must be "manual"). Vercel has treatment
    // "manual" and is not parking, so it reaches this tail — a path the existing
    // suite never took.
    const r = new FakeResolver([ns("site.dev", ["ns1.vercel-dns.com."])]);
    const res = await detect("site.dev", r);
    expect(res.method).toBe("manual");
    expect(res.confidence).toBe(0.8);
    expect(res.dnsHost).toBe("Vercel");
  });
});
