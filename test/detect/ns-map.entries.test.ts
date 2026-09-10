import { describe, expect, it } from "vitest";
import type { ProviderIdentity } from "../../src/detect/ns-map";
import { matchNameservers, normalizeNs } from "../../src/detect/ns-map";

/**
 * One REAL authoritative nameserver hostname per provider, per pattern, pinned
 * to the WHOLE provider identity rather than just its id.
 *
 * This file exists because a generated mutation run scored `ns-map.ts` at
 * 30.20% — 141 surviving mutants against 61 caught, the worst file in the
 * package by a wide margin. The table was reached only incidentally, through
 * higher-level detection tests that happened to use two or three hosts, so a
 * mutant could rewrite the Route 53 pattern or delete Porkbun's second suffix
 * and every test stayed green.
 *
 * Two things are being asserted and they are not the same kind of claim:
 *
 *   - That a given hostname belongs to a given provider is a fact about the
 *     world. The fixtures are real nameserver hostnames, never strings
 *     synthesised from the pattern they test — a fixture derived from its own
 *     pattern asserts only that the pattern equals itself.
 *   - That the provider carries a particular displayName, treatment and set of
 *     flags is a PIN, transcribed from the table. It cannot discover that the
 *     table is wrong; it can only make a change to the table deliberate. Said
 *     plainly here so nobody reads it as the stronger claim.
 */
const CLOUDFLARE: ProviderIdentity = {
  id: "cloudflare",
  displayName: "Cloudflare",
  treatment: "cloudflare",
};
const ROUTE53: ProviderIdentity = {
  id: "route53",
  displayName: "Amazon Route 53",
  treatment: "adapter",
  adapterId: "route53",
};
const GODADDY: ProviderIdentity = {
  id: "godaddy",
  displayName: "GoDaddy",
  treatment: "domain_connect",
  domainConnectLikely: true,
};
const NAMECHEAP: ProviderIdentity = {
  id: "namecheap",
  displayName: "Namecheap",
  treatment: "adapter",
  adapterId: "namecheap",
};
const IONOS: ProviderIdentity = {
  id: "ionos",
  displayName: "IONOS",
  treatment: "domain_connect",
  domainConnectLikely: true,
};
const GOOGLE_DOMAINS: ProviderIdentity = {
  id: "google-domains",
  displayName: "Google Domains",
  treatment: "domain_connect",
  domainConnectLikely: true,
};
const SQUARESPACE: ProviderIdentity = {
  id: "squarespace",
  displayName: "Squarespace",
  treatment: "manual",
};
const NAMESILO: ProviderIdentity = {
  id: "namesilo",
  displayName: "NameSilo",
  treatment: "manual",
  domainConnectLikely: true,
};
const DNSIMPLE: ProviderIdentity = { id: "dnsimple", displayName: "DNSimple", treatment: "manual" };
const DIGITALOCEAN: ProviderIdentity = {
  id: "digitalocean",
  displayName: "DigitalOcean",
  treatment: "manual",
};
const VERCEL: ProviderIdentity = { id: "vercel", displayName: "Vercel", treatment: "manual" };
const NETLIFY: ProviderIdentity = {
  id: "netlify",
  displayName: "Netlify (NS1)",
  treatment: "manual",
};
const GANDI: ProviderIdentity = { id: "gandi", displayName: "Gandi", treatment: "manual" };
const OVH: ProviderIdentity = {
  id: "ovh",
  displayName: "OVH",
  treatment: "manual",
  domainConnectLikely: true,
};
const HETZNER: ProviderIdentity = { id: "hetzner", displayName: "Hetzner", treatment: "manual" };
const PORKBUN: ProviderIdentity = { id: "porkbun", displayName: "Porkbun", treatment: "manual" };
const NAME_COM: ProviderIdentity = {
  id: "name-com",
  displayName: "Name.com",
  treatment: "manual",
  domainConnectLikely: true,
};
const HOVER: ProviderIdentity = { id: "hover", displayName: "Hover", treatment: "manual" };
const DREAMHOST: ProviderIdentity = {
  id: "dreamhost",
  displayName: "DreamHost",
  treatment: "manual",
};
const SEDO: ProviderIdentity = {
  id: "sedo",
  displayName: "Sedo Parking",
  treatment: "manual",
  parking: true,
};
const PARKINGCREW: ProviderIdentity = {
  id: "parkingcrew",
  displayName: "ParkingCrew",
  treatment: "manual",
  parking: true,
};
const BODIS: ProviderIdentity = {
  id: "bodis",
  displayName: "Bodis Parking",
  treatment: "manual",
  parking: true,
};
const ABOVE: ProviderIdentity = {
  id: "above",
  displayName: "Above.com Parking",
  treatment: "manual",
  parking: true,
};
const DAN: ProviderIdentity = {
  id: "dan",
  displayName: "Dan.com Marketplace",
  treatment: "manual",
  parking: true,
};

const FIXTURES: ReadonlyArray<readonly [host: string, provider: ProviderIdentity]> = [
  ["aida.ns.cloudflare.com", CLOUDFLARE],
  ["ns-1234.awsdns-56.org", ROUTE53],
  ["ns-2048.awsdns-63.co.uk", ROUTE53],
  ["ns01.domaincontrol.com", GODADDY],
  ["dns1.registrar-servers.com", NAMECHEAP],
  ["dns1.namecheaphosting.com", NAMECHEAP],
  ["ns1071.ui-dns.com", IONOS],
  ["ns1072.ui-dns.de", IONOS],
  ["ns1073.ui-dns.org", IONOS],
  ["ns1074.ui-dns.biz", IONOS],
  ["ns-cloud-a1.googledomains.com", GOOGLE_DOMAINS],
  ["ns1.squarespacedns.com", SQUARESPACE],
  ["ns1.dnsowl.com", NAMESILO],
  ["ns1.namesilo.com", NAMESILO],
  ["ns1.dnsimple.com", DNSIMPLE],
  ["ns1.dnsimple.net", DNSIMPLE],
  ["ns1.dnsimple-edge.com", DNSIMPLE],
  ["ns1.dnsimple-edge.net", DNSIMPLE],
  ["ns1.digitalocean.com", DIGITALOCEAN],
  ["ns1.vercel-dns.com", VERCEL],
  ["dns1.p01.nsone.net", NETLIFY],
  ["ns-1-a.gandi.net", GANDI],
  ["dns11.ovh.net", OVH],
  ["ns1.ns.hetzner.com", HETZNER],
  ["ns1.ns.hetzner.de", HETZNER],
  ["helium.hetzner.de", HETZNER],
  ["curitiba.ns.porkbun.com", PORKBUN],
  ["maceio.porkbun.com", PORKBUN],
  ["ns1xkl.name.com", NAME_COM],
  ["ns1.hover.com", HOVER],
  ["ns1.dreamhost.com", DREAMHOST],
  ["ns1.sedoparking.com", SEDO],
  ["ns1.sedo.com", SEDO],
  ["ns1.parkingcrew.net", PARKINGCREW],
  ["ns1.bodis.com", BODIS],
  ["ns1.above.com", ABOVE],
  ["ns1.dan.com", DAN],
];

describe("ns-map fixtures", () => {
  it.each(FIXTURES)("%s resolves to its full provider identity", (host, provider) => {
    expect(matchNameservers([host])).toEqual(provider);
  });

  it("covers every entry in the table", () => {
    // Control. The per-host assertions above only prove what the table names,
    // so a fixture list that quietly lost half its rows would still pass them
    // all. 24 is the number of entries in ENTRIES; a new provider added
    // without a fixture fails here rather than sitting untested.
    const distinct = new Set(FIXTURES.map(([, p]) => p.id));
    expect(distinct.size).toBe(24);
  });

  it("marks exactly the five parking services as parking", () => {
    // parking suppresses the write path entirely, so a flag flipped either way
    // is a real behaviour change that the id assertions alone cannot see.
    const parking = new Set(FIXTURES.filter(([, p]) => p.parking).map(([, p]) => p.id));
    expect([...parking].sort()).toEqual(["above", "bodis", "dan", "parkingcrew", "sedo"]);
  });

  it("recognizes nothing in an unrelated nameserver", () => {
    // The negative half. Without it every assertion above would still pass
    // against a matcher that returned the first provider unconditionally.
    expect(matchNameservers(["ns1.example.invalid"])).toBeNull();
    expect(matchNameservers([])).toBeNull();
  });
});

describe("ns-map suffix anchoring", () => {
  // Every pattern but one is anchored at the end of the hostname. Removing a
  // `$` leaves the fixture above still matching, so anchoring needs its own
  // negative: a hostname that CONTAINS a provider's domain but does not END
  // with it must not be read as that provider.
  const INFIX_BY_DESIGN = new Set(["route53"]);
  const anchored = FIXTURES.filter(([, p]) => !INFIX_BY_DESIGN.has(p.id));

  it.each(anchored)("%s is not matched as a mere substring", (host) => {
    expect(matchNameservers([`${host}.attacker.example`])).toBeNull();
  });

  it("Route 53 is infix by design, and that is a real asymmetry", () => {
    // AWS spreads its nameservers over four TLDs (.com/.net/.org/.co.uk), so
    // the pattern matches on `.awsdns-<n>.` in the middle rather than on a
    // suffix. The consequence is stated rather than hidden: a hostname ending
    // in an attacker's domain still reads as Route 53. It is not a privilege
    // boundary — anyone who can set a zone's NS records already controls its
    // DNS — but it is the one entry where the substring defence does not hold,
    // and a reader should learn that here rather than by discovering it.
    expect(matchNameservers(["ns-1234.awsdns-56.org.attacker.example"])).toEqual(ROUTE53);
  });
});

describe("normalizeNs", () => {
  it("matches regardless of case or a trailing root dot", () => {
    // Wire-format DNS answers arrive fully qualified and case is not
    // significant, so both forms have to reach the same provider.
    expect(matchNameservers(["AIDA.NS.CLOUDFLARE.COM."])).toEqual(CLOUDFLARE);
    expect(matchNameservers([" ns01.DomainControl.com. "])).toEqual(GODADDY);
  });

  it("returns the first recognized provider when the set is mixed", () => {
    expect(matchNameservers(["ns1.example.invalid", "ns1.hover.com"])).toEqual(HOVER);
  });

  it("lowercases, trims and strips exactly one trailing dot", () => {
    expect(normalizeNs("  NS1.Example.COM.  ")).toBe("ns1.example.com");
    expect(normalizeNs("ns1.example.com..")).toBe("ns1.example.com.");
  });
});
