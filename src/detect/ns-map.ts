// Latch — authoritative nameserver → provider identity map.
//
// Detection maps on the *authoritative NS suffix*, never on WHOIS/registrar
// (a registrar is not the DNS host — a GoDaddy-registered domain can live on
// Cloudflare NS). See ARCHITECTURE.md §Detection.
//
// Each entry declares WHO the DNS host is (id + displayName) and the best
// automated write path we have for it (`treatment`):
//   - "cloudflare"     → write via the Cloudflare API
//   - "domain_connect" → provider implements the Domain Connect sync flow
//   - "adapter"        → a per-provider adapter (adapterId names it)
//   - "manual"         → recognized host, but no automated writer → polished
//                        manual fallback (we still name the host in the UI)
//
// `treatment` is only a FALLBACK hint. Live Domain Connect discovery
// (see domain-connect.ts) is authoritative and can upgrade ANY recognized or
// unknown host to "domain_connect" when the `_domainconnect` TXT is present.
//
// Patterns are matched case-insensitively against each nameserver hostname
// (lowercased, trailing dot stripped). Non-exhaustive by design — covers the
// large hosts; unknown suffixes fall through to a named-unknown → manual path.

export type ProviderTreatment =
  | "cloudflare"
  | "domain_connect"
  | "adapter"
  | "manual";

export interface ProviderIdentity {
  /** Stable slug, also used to form `adapter:<id>` methods. */
  id: string;
  displayName: string;
  treatment: ProviderTreatment;
  /** Present when treatment === "adapter". */
  adapterId?: string;
  /** This NS belongs to a parking / for-sale service, not a live DNS host. */
  parking?: boolean;
  /**
   * Host is known to implement Domain Connect. Discovery still confirms it at
   * runtime; this only prioritizes the discovery attempt.
   */
  domainConnectLikely?: boolean;
}

interface NsMapEntry {
  /** Matched against each nameserver hostname (already lowercased, no trailing dot). */
  patterns: RegExp[];
  provider: ProviderIdentity;
}

// ---------------------------------------------------------------------------
// The map. Sources are the providers' documented default nameservers.
// ---------------------------------------------------------------------------

const ENTRIES: NsMapEntry[] = [
  // Cloudflare — e.g. aida.ns.cloudflare.com, rick.ns.cloudflare.com
  {
    patterns: [/\.ns\.cloudflare\.com$/],
    provider: { id: "cloudflare", displayName: "Cloudflare", treatment: "cloudflare" },
  },

  // AWS Route 53 — ns-1234.awsdns-56.org / .com / .net / .co.uk
  {
    patterns: [/\.awsdns-\d+\./],
    provider: { id: "route53", displayName: "Amazon Route 53", treatment: "adapter", adapterId: "route53" },
  },

  // GoDaddy — ns01.domaincontrol.com, ns02.domaincontrol.com (Domain Connect reference host)
  {
    patterns: [/\.domaincontrol\.com$/],
    provider: {
      id: "godaddy",
      displayName: "GoDaddy",
      treatment: "domain_connect",
      domainConnectLikely: true,
    },
  },

  // Namecheap — FreeDNS: dns1.registrar-servers.com; hosting: dns1.namecheaphosting.com
  {
    patterns: [/\.registrar-servers\.com$/, /\.namecheaphosting\.com$/],
    provider: { id: "namecheap", displayName: "Namecheap", treatment: "adapter", adapterId: "namecheap" },
  },

  // IONOS / 1&1 — ns1071.ui-dns.com, ns1072.ui-dns.de/.org/.biz (Domain Connect reference implementer)
  {
    patterns: [/\.ui-dns\.(com|de|org|biz)$/],
    provider: {
      id: "ionos",
      displayName: "IONOS",
      treatment: "domain_connect",
      domainConnectLikely: true,
    },
  },

  // Google Domains (migrated to Squarespace) — ns-cloud / googledomains.com
  {
    patterns: [/\.googledomains\.com$/],
    provider: {
      id: "google-domains",
      displayName: "Google Domains",
      treatment: "domain_connect",
      domainConnectLikely: true,
    },
  },
  // Squarespace-managed DNS — ns1.squarespacedns.com (recognized; no automated writer)
  {
    patterns: [/\.squarespacedns\.com$/],
    provider: { id: "squarespace", displayName: "Squarespace", treatment: "manual" },
  },

  // NameSilo — default NS live on dnsowl.com (ns1/ns2/ns3.dnsowl.com)
  {
    patterns: [/\.dnsowl\.com$/, /\.namesilo\.com$/],
    provider: { id: "namesilo", displayName: "NameSilo", treatment: "manual", domainConnectLikely: true },
  },

  // DNSimple — ns1.dnsimple.com, ns2.dnsimple-edge.net, ns3.dnsimple.net
  {
    patterns: [/\.dnsimple(-edge)?\.(com|net)$/],
    provider: { id: "dnsimple", displayName: "DNSimple", treatment: "manual" },
  },

  // DigitalOcean — ns1.digitalocean.com, ns2/ns3.digitalocean.com
  {
    patterns: [/\.digitalocean\.com$/],
    provider: { id: "digitalocean", displayName: "DigitalOcean", treatment: "manual" },
  },

  // Vercel — ns1.vercel-dns.com, ns2.vercel-dns.com
  {
    patterns: [/\.vercel-dns\.com$/],
    provider: { id: "vercel", displayName: "Vercel", treatment: "manual" },
  },

  // Netlify DNS — runs on NS1 infra: dns1.p0X.nsone.net (nsone.net is the NS1 anycast domain)
  {
    patterns: [/\.nsone\.net$/],
    provider: { id: "netlify", displayName: "Netlify (NS1)", treatment: "manual" },
  },

  // Gandi LiveDNS — ns-1-a.gandi.net, ns-2-b.gandi.net, ns-3-c.gandi.net
  {
    patterns: [/\.gandi\.net$/],
    provider: { id: "gandi", displayName: "Gandi", treatment: "manual" },
  },

  // OVH — dns1.ovh.net, ns1.ovh.net
  {
    patterns: [/\.ovh\.net$/],
    provider: { id: "ovh", displayName: "OVH", treatment: "manual", domainConnectLikely: true },
  },

  // Hetzner — hydrogen.ns.hetzner.com, oxygen.ns.hetzner.com, helium.ns.hetzner.de
  {
    patterns: [/\.ns\.hetzner\.(com|de)$/, /\.hetzner\.(com|de)$/],
    provider: { id: "hetzner", displayName: "Hetzner", treatment: "manual" },
  },

  // Porkbun — curitiba/fortaleza/salvador/maceio.ns.porkbun.com
  {
    patterns: [/\.ns\.porkbun\.com$/, /\.porkbun\.com$/],
    provider: { id: "porkbun", displayName: "Porkbun", treatment: "manual" },
  },

  // Name.com — ns1xxx.name.com
  {
    patterns: [/\.name\.com$/],
    provider: { id: "name-com", displayName: "Name.com", treatment: "manual", domainConnectLikely: true },
  },

  // Hover — ns1.hover.com, ns2.hover.com
  {
    patterns: [/\.hover\.com$/],
    provider: { id: "hover", displayName: "Hover", treatment: "manual" },
  },

  // DreamHost — ns1.dreamhost.com, ns2/ns3.dreamhost.com
  {
    patterns: [/\.dreamhost\.com$/],
    provider: { id: "dreamhost", displayName: "DreamHost", treatment: "manual" },
  },

  // ---- Parking / for-sale services (a live host, but no user zone to write) ----
  {
    patterns: [/\.sedoparking\.com$/, /\.sedo\.com$/],
    provider: { id: "sedo", displayName: "Sedo Parking", treatment: "manual", parking: true },
  },
  {
    patterns: [/\.parkingcrew\.net$/],
    provider: { id: "parkingcrew", displayName: "ParkingCrew", treatment: "manual", parking: true },
  },
  {
    patterns: [/\.bodis\.com$/],
    provider: { id: "bodis", displayName: "Bodis Parking", treatment: "manual", parking: true },
  },
  {
    patterns: [/\.above\.com$/],
    provider: { id: "above", displayName: "Above.com Parking", treatment: "manual", parking: true },
  },
  {
    patterns: [/\.dan\.com$/],
    provider: { id: "dan", displayName: "Dan.com Marketplace", treatment: "manual", parking: true },
  },
];

/** Normalize a nameserver hostname for matching: lowercase, strip a trailing dot. */
export function normalizeNs(ns: string): string {
  return ns.trim().toLowerCase().replace(/\.$/, "");
}

/**
 * Match a set of authoritative nameservers to a provider identity. Returns the
 * first provider any nameserver matches, or null when none is recognized.
 */
export function matchNameservers(nameservers: string[]): ProviderIdentity | null {
  for (const raw of nameservers) {
    const ns = normalizeNs(raw);
    for (const entry of ENTRIES) {
      if (entry.patterns.some((p) => p.test(ns))) {
        return entry.provider;
      }
    }
  }
  return null;
}
