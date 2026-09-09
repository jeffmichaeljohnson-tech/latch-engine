import { describe, it, expect } from "vitest";
import { detect } from "../../src/detect/detect";
import {
  discoverDomainConnect,
  settingsUrl,
  type SettingsFetcher,
} from "../../src/detect/domain-connect";
import { matchNameservers } from "../../src/detect/ns-map";
import type {
  Resolver,
  DnsResponse,
  DnsQueryType,
  QueryOptions,
} from "../../src/net/resolver";

// --- Fake resolver: canned responses keyed by "<name>|<TYPE>", no network. ---

const RR: Record<DnsQueryType, number> = {
  A: 1,
  AAAA: 28,
  CNAME: 5,
  MX: 15,
  TXT: 16,
  NS: 2,
  SOA: 6,
  CAA: 257,
  DS: 43,
  DNSKEY: 48,
};

function ns(name: string, hosts: string[]): [string, DnsResponse] {
  return [
    `${name}|NS`,
    { Status: 0, Answer: hosts.map((h) => ({ name, type: RR.NS, TTL: 3600, data: h })) },
  ];
}

function mx(name: string, entries: string[]): [string, DnsResponse] {
  return [
    `${name}|MX`,
    { Status: 0, Answer: entries.map((d) => ({ name, type: RR.MX, TTL: 3600, data: d })) },
  ];
}

function txt(name: string, values: string[]): [string, DnsResponse] {
  return [
    `${name}|TXT`,
    { Status: 0, Answer: values.map((v) => ({ name, type: RR.TXT, TTL: 3600, data: `"${v}"` })) },
  ];
}

function ds(name: string): [string, DnsResponse] {
  return [
    `${name}|DS`,
    { Status: 0, AD: true, Answer: [{ name, type: RR.DS, TTL: 3600, data: "12345 13 2 abc" }] },
  ];
}

// The four DNSSEC signals are deliberately separable. `ds()` above sets AD *and*
// carries an answer, so it proves the detector as a whole but cannot distinguish
// which branch fired — disabling either one alone left the suite green.
function nsSigned(name: string, hosts: string[]): [string, DnsResponse] {
  return [
    `${name}|NS`,
    { Status: 0, AD: true, Answer: hosts.map((h) => ({ name, type: RR.NS, TTL: 3600, data: h })) },
  ];
}

function dsAnswerOnly(name: string): [string, DnsResponse] {
  return [
    `${name}|DS`,
    { Status: 0, AD: false, Answer: [{ name, type: RR.DS, TTL: 3600, data: "12345 13 2 abc" }] },
  ];
}

function dsAdOnly(name: string): [string, DnsResponse] {
  return [`${name}|DS`, { Status: 0, AD: true, Answer: [] }];
}

function dnskey(name: string): [string, DnsResponse] {
  return [
    `${name}|DNSKEY`,
    { Status: 0, AD: false, Answer: [{ name, type: RR.DNSKEY, TTL: 3600, data: "257 3 13 abc" }] },
  ];
}

class FakeResolver implements Resolver {
  private readonly map: Map<string, DnsResponse>;
  readonly seen: string[] = [];

  constructor(entries: Array<[string, DnsResponse]>) {
    this.map = new Map(entries);
  }

  async query(name: string, type: DnsQueryType, _opts?: QueryOptions): Promise<DnsResponse> {
    const key = `${name}|${type}`;
    this.seen.push(key);
    return this.map.get(key) ?? { Status: 0, Answer: [] };
  }
}

const settingsFor =
  (doc: Record<string, unknown> | null): SettingsFetcher =>
  async () =>
    doc as never;

describe("detect() — provider detection", () => {
  it("Cloudflare NS → method cloudflare", async () => {
    const r = new FakeResolver([ns("acme.com", ["aida.ns.cloudflare.com.", "rick.ns.cloudflare.com."])]);
    const res = await detect("acme.com", r);
    expect(res.method).toBe("cloudflare");
    expect(res.dnsHost).toBe("Cloudflare");
    expect(res.registered).toBe(true);
    expect(res.nameservers).toContain("aida.ns.cloudflare.com");
    expect(res.confidence).toBeGreaterThan(0.8);
  });

  it("GoDaddy NS + _domainconnect present → method domain_connect with authUrl", async () => {
    const r = new FakeResolver([
      ns("shop.com", ["ns01.domaincontrol.com.", "ns02.domaincontrol.com."]),
      txt("_domainconnect.shop.com", ["domainconnect.godaddy.com"]),
    ]);
    const res = await detect("shop.com", r, {
      fetchSettings: settingsFor({
        providerId: "GoDaddy",
        providerName: "GoDaddy",
        urlSyncUX: "https://domainconnect.godaddy.com/sync",
        urlAPI: "https://domainconnect.godaddy.com/api",
      }),
    });
    expect(res.method).toBe("domain_connect");
    expect(res.authUrl).toBe("https://domainconnect.godaddy.com/sync");
    expect(res.dnsHost).toBe("GoDaddy");
    expect(res.confidence).toBeGreaterThan(0.9);
  });

  it("GoDaddy NS but discovery unavailable → falls back to manual (still named)", async () => {
    const r = new FakeResolver([ns("shop.com", ["ns01.domaincontrol.com."])]);
    const res = await detect("shop.com", r); // no fetchSettings → no discovery
    expect(res.method).toBe("manual");
    expect(res.dnsHost).toBe("GoDaddy");
  });

  it("Route 53 NS → method adapter:route53", async () => {
    const r = new FakeResolver([
      ns("infra.io", ["ns-1234.awsdns-56.org.", "ns-789.awsdns-01.co.uk."]),
    ]);
    const res = await detect("infra.io", r);
    expect(res.method).toBe("adapter:route53");
    expect(res.dnsHost).toBe("Amazon Route 53");
  });

  it("unknown NS → method manual, low confidence, dnsHost null", async () => {
    const r = new FakeResolver([ns("weird.example", ["ns1.some-unknown-host.tld.", "ns2.some-unknown-host.tld."])]);
    const res = await detect("weird.example", r);
    expect(res.method).toBe("manual");
    expect(res.dnsHost).toBeNull();
    expect(res.registered).toBe(true);
    expect(res.confidence).toBeLessThan(0.5);
  });

  it("NXDOMAIN → registered:false", async () => {
    const r = new FakeResolver([["nope.test|NS", { Status: 3, Answer: [] }]]);
    const res = await detect("nope.test", r);
    expect(res.registered).toBe(false);
    expect(res.method).toBe("manual");
    expect(res.nameservers).toEqual([]);
  });

  it("registered but not delegated (no NS) → manual", async () => {
    const r = new FakeResolver([["orphan.test|NS", { Status: 0, Answer: [] }]]);
    const res = await detect("orphan.test", r);
    expect(res.registered).toBe(true);
    expect(res.method).toBe("manual");
    expect(res.dnsHost).toBeNull();
  });

  it("existing MX is populated (targets, trailing dot stripped)", async () => {
    const r = new FakeResolver([
      ns("mailer.com", ["aida.ns.cloudflare.com."]),
      mx("mailer.com", ["10 aspmx.l.google.com.", "20 alt1.aspmx.l.google.com."]),
    ]);
    const res = await detect("mailer.com", r);
    expect(res.existingMx).toEqual(["aspmx.l.google.com", "alt1.aspmx.l.google.com"]);
  });

  it("null MX (0 .) is not treated as a live mail target", async () => {
    const r = new FakeResolver([
      ns("nomail.com", ["aida.ns.cloudflare.com."]),
      mx("nomail.com", ["0 ."]),
    ]);
    const res = await detect("nomail.com", r);
    expect(res.existingMx).toEqual([]);
  });

  it("DNSSEC flagged when a DS record exists", async () => {
    const r = new FakeResolver([
      ns("secure.com", ["aida.ns.cloudflare.com."]),
      ds("secure.com"),
    ]);
    const res = await detect("secure.com", r);
    expect(res.dnssec).toBe(true);
  });

  it("no DNSSEC when no DS/DNSKEY/AD", async () => {
    const r = new FakeResolver([ns("plain.com", ["aida.ns.cloudflare.com."])]);
    const res = await detect("plain.com", r);
    expect(res.dnssec).toBe(false);
  });

  // Each signal on its own. Found by mutation: every branch of detectDnssec
  // could be disabled individually with the suite staying green, because the
  // one positive case above fires two of them at once and never reaches the
  // DNSKEY fallback at all.
  it("DNSSEC via the NS query's AD flag alone", async () => {
    const r = new FakeResolver([nsSigned("ad.com", ["aida.ns.cloudflare.com."])]);
    expect((await detect("ad.com", r)).dnssec).toBe(true);
  });

  it("DNSSEC via the DS query's AD flag alone, with no DS answer", async () => {
    const r = new FakeResolver([
      ns("dsad.com", ["aida.ns.cloudflare.com."]),
      dsAdOnly("dsad.com"),
    ]);
    expect((await detect("dsad.com", r)).dnssec).toBe(true);
  });

  it("DNSSEC via a DS answer alone, with AD false", async () => {
    const r = new FakeResolver([
      ns("dsans.com", ["aida.ns.cloudflare.com."]),
      dsAnswerOnly("dsans.com"),
    ]);
    expect((await detect("dsans.com", r)).dnssec).toBe(true);
  });

  it("DNSSEC via a DNSKEY answer alone, with no DS and no AD", async () => {
    const r = new FakeResolver([
      ns("dk.com", ["aida.ns.cloudflare.com."]),
      dnskey("dk.com"),
    ]);
    expect((await detect("dk.com", r)).dnssec).toBe(true);
  });

  it("parked pattern → parked:true, method manual", async () => {
    const r = new FakeResolver([ns("forsale.com", ["ns1.sedoparking.com.", "ns2.sedoparking.com."])]);
    const res = await detect("forsale.com", r);
    expect(res.parked).toBe(true);
    expect(res.method).toBe("manual");
    expect(res.dnsHost).toBe("Sedo Parking");
  });

  it("Domain Connect discovery works even on an NS host the map doesn't recognize", async () => {
    const r = new FakeResolver([
      ns("indie.dev", ["ns1.some-unknown-host.tld."]),
      txt("_domainconnect.indie.dev", ["dc.some-unknown-host.tld"]),
    ]);
    const res = await detect("indie.dev", r, {
      fetchSettings: settingsFor({
        providerName: "IndieHost",
        urlAsyncUX: "https://dc.some-unknown-host.tld/async",
      }),
    });
    expect(res.method).toBe("domain_connect");
    expect(res.authUrl).toBe("https://dc.some-unknown-host.tld/async");
    expect(res.dnsHost).toBe("IndieHost");
  });

  it("input domain is normalized (trailing dot, case)", async () => {
    const r = new FakeResolver([ns("acme.com", ["aida.ns.cloudflare.com."])]);
    const res = await detect("ACME.com.", r);
    expect(res.domain).toBe("acme.com");
    expect(res.method).toBe("cloudflare");
  });
});

describe("discoverDomainConnect()", () => {
  it("returns supported with endpoints when TXT + settings resolve", async () => {
    const r = new FakeResolver([txt("_domainconnect.shop.com", ["domainconnect.godaddy.com"])]);
    const out = await discoverDomainConnect(
      "shop.com",
      r,
      settingsFor({ providerId: "GoDaddy", urlSyncUX: "https://x/sync" }),
    );
    expect(out.supported).toBe(true);
    expect(out.providerId).toBe("GoDaddy");
    expect(out.urlSyncUX).toBe("https://x/sync");
  });

  it("unsupported when no _domainconnect TXT", async () => {
    const r = new FakeResolver([]);
    const out = await discoverDomainConnect("bare.com", r, settingsFor({ urlSyncUX: "x" }));
    expect(out.supported).toBe(false);
  });

  it("unsupported when settings advertise no flow endpoint", async () => {
    const r = new FakeResolver([txt("_domainconnect.x.com", ["dc.x.com"])]);
    const out = await discoverDomainConnect("x.com", r, settingsFor({ providerId: "X" }));
    expect(out.supported).toBe(false);
  });

  it("unsupported (never throws) when the settings fetch fails", async () => {
    const r = new FakeResolver([txt("_domainconnect.x.com", ["dc.x.com"])]);
    const throwing: SettingsFetcher = async () => {
      throw new Error("network down");
    };
    const out = await discoverDomainConnect("x.com", r, throwing);
    expect(out.supported).toBe(false);
  });
});

describe("settingsUrl()", () => {
  it("builds from a bare host", () => {
    expect(settingsUrl("domainconnect.godaddy.com", "shop.com")).toBe(
      "https://domainconnect.godaddy.com/v2/shop.com/settings",
    );
  });
  it("builds from a full URL, stripping a trailing slash", () => {
    expect(settingsUrl("https://dc.example.com/", "a.com")).toBe(
      "https://dc.example.com/v2/a.com/settings",
    );
  });
});

describe("matchNameservers()", () => {
  it("matches case-insensitively and ignores trailing dots", () => {
    expect(matchNameservers(["NS01.DomainControl.com."])?.id).toBe("godaddy");
  });
  it("returns null for an unrecognized suffix", () => {
    expect(matchNameservers(["ns1.mystery.tld"])).toBeNull();
  });
});
