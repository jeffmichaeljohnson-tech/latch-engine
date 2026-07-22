// Latch — apex (zone-root) record handling.
//
// A literal CNAME at the apex is illegal: RFC 1034 forbids a CNAME coexisting with
// the SOA/NS (and MX/TXT) that every apex must carry. Hosts solve this with ALIAS
// or CNAME-flattening; where unavailable we fall back to A/AAAA. Flattening must be
// ADDITIVE — it never drops coexisting MX/TXT. Pure: the caller resolves any IPs.

import type { DnsRecord } from "../types";
import { LatchError } from "../types";
import { clampTtl, normalizeFqdn } from "./vars";

/** True when `host` denotes the zone apex ("@", empty, or the bare registrable domain). */
export function isApexHost(host: string, apex?: string): boolean {
  const h = host.trim().replace(/\.$/, "").toLowerCase();
  if (h === "@" || h === "") return true;
  if (apex !== undefined) return h === apex.trim().replace(/\.$/, "").toLowerCase();
  return false;
}

/**
 * Refuse a literal CNAME at the apex (RFC 1034). Throws LatchError("unsupported")
 * so the caller routes to planApex() instead of writing an illegal record.
 */
export function assertNoApexCname(record: DnsRecord, apex?: string): void {
  if (record.type === "CNAME" && isApexHost(record.host, apex)) {
    throw new LatchError(
      "unsupported",
      `A CNAME at the apex (${record.host}) is illegal — it cannot coexist with the SOA/NS records (RFC 1034). Use ALIAS/flattening or A/AAAA.`,
    );
  }
}

/** An ALIAS pseudo-record. ALIAS is not a real RR type, so it is NOT a DnsRecord. */
export interface AliasRecord {
  type: "ALIAS";
  host: string;
  value: string;
  ttl: number;
}

export interface ApexTargetPlan {
  /** Does the DNS host offer ALIAS / CNAME-flattening at the apex? */
  supportsApex: boolean;
  /** The hostname we wanted to CNAME the apex to. */
  target: string;
  /** Resolved A/AAAA addresses for the flatten fallback (caller resolves; engine stays pure). */
  resolved?: { a?: string[]; aaaa?: string[] };
  ttl?: number;
}

export type ApexPlan =
  | { strategy: "alias"; record: AliasRecord }
  | { strategy: "flatten"; records: DnsRecord[] }
  | { strategy: "unresolved"; reason: string };

/**
 * Decide how to point the apex at `target`:
 * - host supports apex CNAME    -> a single ALIAS record.
 * - otherwise, with resolved IPs -> flatten to A/AAAA (additive; caller merges,
 *   preserving coexisting MX/TXT).
 * - otherwise                   -> "unresolved": the caller must resolve IPs first.
 */
export function planApex(input: ApexTargetPlan): ApexPlan {
  const ttl = clampTtl(input.ttl, 300);

  if (input.supportsApex) {
    return {
      strategy: "alias",
      record: { type: "ALIAS", host: "@", value: normalizeFqdn(input.target), ttl },
    };
  }

  const a = input.resolved?.a ?? [];
  const aaaa = input.resolved?.aaaa ?? [];
  if (a.length === 0 && aaaa.length === 0) {
    return {
      strategy: "unresolved",
      reason: `Host does not support ALIAS at the apex and no A/AAAA addresses were supplied to flatten ${input.target}. Resolve the target first, then flatten.`,
    };
  }

  const records: DnsRecord[] = [
    ...a.map((ip): DnsRecord => ({ type: "A", host: "@", value: ip, ttl, purpose: "site" })),
    ...aaaa.map((ip): DnsRecord => ({ type: "AAAA", host: "@", value: ip, ttl, purpose: "site" })),
  ];
  return { strategy: "flatten", records };
}
