// Latch — DNS-over-HTTPS resolver seam.
//
// A minimal, injectable resolver used by ./detect and ./verify. Both run inside a
// Cloudflare Worker (no raw UDP/53) and in Node, so all lookups go over DoH JSON.
//
// Injectable on purpose: production uses DohResolver; tests pass a fake Resolver
// with canned responses (never hit the network in unit tests).
//
// LIMITATION (documented, not a bug): public DoH endpoints answer *recursively*
// (their cache), not from the zone's authoritative nameservers. For confirming our
// own writes, the authoritative-truth path is a CF-API read-back on owned zones
// (see providers/) or a sidecar hickory-dns helper (phase 2). This resolver's
// `verify` usage is the public-propagation signal + multi-resolver cross-check.

export type DnsQueryType =
  | "A"
  | "AAAA"
  | "CNAME"
  | "MX"
  | "TXT"
  | "NS"
  | "SOA"
  | "CAA"
  | "DS"
  | "DNSKEY";

/** One record from a DoH JSON answer. `type` is the numeric RR type. */
export interface DnsAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

/** RFC 8484 / Google-style DoH JSON response. `Status` is the DNS RCODE (0 = NOERROR, 3 = NXDOMAIN). */
export interface DnsResponse {
  Status: number;
  /** Authenticated Data — set when the answer passed DNSSEC validation at the resolver. */
  AD?: boolean;
  Answer?: DnsAnswer[];
  Authority?: DnsAnswer[];
}

export interface QueryOptions {
  /** DoH endpoint base to use (defaults to the resolver's primary). */
  endpoint?: string;
  /** Request DNSSEC validation (sets the `do` flag); AD in the response reflects it. */
  dnssec?: boolean;
}

export interface Resolver {
  query(name: string, type: DnsQueryType, opts?: QueryOptions): Promise<DnsResponse>;
}

/** Numeric RR type → name, for reading DnsAnswer.type. */
export const RR_TYPE: Record<number, DnsQueryType> = {
  1: "A",
  28: "AAAA",
  5: "CNAME",
  15: "MX",
  16: "TXT",
  2: "NS",
  6: "SOA",
  257: "CAA",
  43: "DS",
  48: "DNSKEY",
};

/** Public DoH JSON endpoints. Cross-check across resolvers to gauge propagation. */
export const DOH_ENDPOINTS = {
  cloudflare: "https://cloudflare-dns.com/dns-query",
  google: "https://dns.google/resolve",
} as const;

/**
 * Default DoH resolver over the JSON API. Worker- and Node-compatible (uses global fetch).
 * Primary endpoint is Cloudflare; pass a different `endpoint` per query for multi-resolver checks.
 */
export class DohResolver implements Resolver {
  constructor(private readonly primary: string = DOH_ENDPOINTS.cloudflare) {}

  async query(name: string, type: DnsQueryType, opts: QueryOptions = {}): Promise<DnsResponse> {
    const base = opts.endpoint ?? this.primary;
    const url = new URL(base);
    url.searchParams.set("name", name);
    url.searchParams.set("type", type);
    if (opts.dnssec) url.searchParams.set("do", "1");

    const res = await fetch(url.toString(), {
      headers: { accept: "application/dns-json" },
    });
    if (!res.ok) {
      throw new Error(`DoH query failed (${res.status}) for ${type} ${name}`);
    }
    return (await res.json()) as DnsResponse;
  }
}

/** Read all TXT strings for a name from a DoH response, unquoting DoH's quoted form. */
export function readTxt(resp: DnsResponse): string[] {
  return (resp.Answer ?? [])
    .filter((a) => a.type === 16)
    .map((a) => unquoteTxt(a.data));
}

/**
 * DoH returns TXT data as one or more quoted strings, e.g. `"v=spf1 …" "…"`.
 * Concatenate the quoted chunks into the logical value (RFC 1035 multi-string TXT).
 */
export function unquoteTxt(data: string): string {
  const chunks = data.match(/"((?:[^"\\]|\\.)*)"/g);
  if (!chunks) return data;
  return chunks.map((c) => c.slice(1, -1).replace(/\\(.)/g, "$1")).join("");
}
