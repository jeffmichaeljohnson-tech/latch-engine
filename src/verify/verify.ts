// Latch — verify: query expected records across multiple DoH resolvers, compare
// values by record type, and produce a two-tier VerifyResult; plus pollUntil,
// which drives verifyOnce on the backoff schedule to a terminal status.
//
// Never opens a socket: all lookups go through the injected Resolver (production
// passes DohResolver; tests pass a fake). Never reads the wall clock: pollUntil
// takes injected `sleep` + `now`, so the schedule is deterministic and Worker-safe.

import type { DnsRecord, VerifyResult, RecordVerifyState } from "../types";
import {
  DOH_ENDPOINTS,
  readTxt,
  unquoteTxt,
  type Resolver,
  type DnsResponse,
  type DnsAnswer,
} from "../net/resolver";
import { nextDelayMs } from "./schedule";
import {
  recordStatus,
  rollupStatus,
  type RecordObservation,
} from "./status";

/** Per-record authoritative signal, or a single flag applied to all records. */
export type AuthoritativeConfirmed =
  | boolean
  | ((rec: DnsRecord) => boolean | undefined);

export interface VerifyOptions {
  /** DoH endpoints to cross-check. Defaults to Cloudflare + Google. */
  endpoints?: readonly string[];
  /** Owned-zone authoritative read-back (CF-API). Wins over recursive DoH. */
  authoritativeConfirmed?: AuthoritativeConfirmed;
  /** Request DNSSEC validation on each query. */
  dnssec?: boolean;
}

/** Default multi-resolver set: cross-check Cloudflare against Google. */
const DEFAULT_ENDPOINTS: readonly string[] = [
  DOH_ENDPOINTS.cloudflare,
  DOH_ENDPOINTS.google,
];

// ---------------------------------------------------------------------------
// Name + value normalization
// ---------------------------------------------------------------------------

/** Resolve a record `host` ("@" / label / FQDN) to the fully-qualified name to query. */
export function toFqdn(host: string, domain: string): string {
  const h = host.trim().replace(/\.$/, "");
  if (h === "" || h === "@") return domain;
  if (h === domain || h.endsWith("." + domain)) return h;
  return `${h}.${domain}`;
}

/** Case-insensitive host compare, tolerant of a trailing dot. */
function normHost(s: string): string {
  return s.trim().replace(/\.$/, "").toLowerCase();
}

// The expected value and the resolver's answer are decoded by the SAME function,
// deliberately. A record whose value exceeds 255 octets is written as several
// quoted character-strings that DNS concatenates back into one logical value
// (RFC 1035 3.3.14) -- every 2048-bit DKIM key is one. A decoder that strips only
// the OUTER pair of quotes turns `"aaa" "bbb"` into `aaa" "bbb`, which can never
// equal the `aaabbb` the resolver reports, so a correctly published key verifies
// as absent forever. Two decoders is what allowed the two sides to disagree.

// ---------------------------------------------------------------------------
// Per-type value comparison
// ---------------------------------------------------------------------------

/** Answers of the RR type matching an expected record. */
function answersOfType(resp: DnsResponse, rrType: number): DnsAnswer[] {
  return (resp.Answer ?? []).filter((a) => a.type === rrType);
}

/** Numeric RR type for an expected record's type. */
const RR_NUM: Record<DnsRecord["type"], number> = {
  A: 1,
  AAAA: 28,
  CNAME: 5,
  CAA: 257,
  MX: 15,
  TXT: 16,
  NS: 2,
};

/**
 * Does this resolver's response contain the expected record value?
 *  - TXT   : any logical (multi-string-concatenated) TXT equals the expected value
 *  - MX     : any answer matches target (host-normalized) AND priority
 *  - CNAME/A/AAAA/NS/CAA : any answer's target/value matches (host-normalized)
 */
export function responseMatches(resp: DnsResponse, expected: DnsRecord): boolean {
  if (expected.type === "TXT") {
    const want = unquoteTxt(expected.value);
    return readTxt(resp).some((v) => v === want);
  }

  const answers = answersOfType(resp, RR_NUM[expected.type]);

  if (expected.type === "MX") {
    const wantTarget = normHost(expected.value);
    const wantPrio = expected.priority;
    return answers.some((a) => {
      const parts = a.data.trim().split(/\s+/);
      if (parts.length < 2) return false;
      const prio = Number(parts[0]);
      const target = normHost(parts.slice(1).join(" "));
      const prioOk = wantPrio === undefined ? true : prio === wantPrio;
      return prioOk && target === wantTarget;
    });
  }

  // CNAME / A / AAAA / NS / CAA — compare the answer datum host-normalized.
  const want = normHost(expected.value);
  return answers.some((a) => normHost(a.data) === want);
}

// ---------------------------------------------------------------------------
// verifyOnce
// ---------------------------------------------------------------------------

/** Resolve the caller-supplied authoritative signal for one record. */
function authFor(
  rec: DnsRecord,
  flag: AuthoritativeConfirmed | undefined,
): boolean | undefined {
  if (flag === undefined) return undefined;
  if (typeof flag === "function") return flag(rec);
  return flag;
}

/**
 * Query every expected record across the resolver endpoints once, compare values,
 * and produce per-record states + an overall status. No timers, no retries.
 */
export async function verifyOnce(
  domain: string,
  expected: readonly DnsRecord[],
  resolver: Resolver,
  opts: VerifyOptions = {},
): Promise<VerifyResult> {
  const endpoints = opts.endpoints ?? DEFAULT_ENDPOINTS;
  const records: RecordVerifyState[] = [];

  for (const rec of expected) {
    const name = toFqdn(rec.host, domain);
    let confirmed = 0;
    let clean = 0;
    let errors = 0;

    for (const endpoint of endpoints) {
      try {
        const resp = await resolver.query(name, rec.type, {
          endpoint,
          dnssec: opts.dnssec,
        });
        clean += 1;
        if (responseMatches(resp, rec)) confirmed += 1;
      } catch {
        errors += 1;
      }
    }

    const obs: RecordObservation = {
      confirmed,
      total: clean,
      errors,
      authoritativeConfirmed: authFor(rec, opts.authoritativeConfirmed),
    };
    records.push({ type: rec.type, host: rec.host, status: recordStatus(obs) });
  }

  return { domain, status: rollupStatus(records), records };
}

// ---------------------------------------------------------------------------
// pollUntil
// ---------------------------------------------------------------------------

export interface PollDeps {
  /** Injected sleep — tests pass a fake that advances the injected clock. */
  sleep: (ms: number) => Promise<void>;
  /** Injected monotonic clock (ms). Never Date.now() in logic. */
  now: () => number;
  endpoints?: readonly string[];
  authoritativeConfirmed?: AuthoritativeConfirmed;
  dnssec?: boolean;
  /** Optional jobId to stamp on the result. */
  jobId?: string;
}

/**
 * Drive verifyOnce on the backoff schedule until the status is terminal:
 *   - "published" (authoritative) or "confirmed" (public-resolver terminal) → return it
 *   - hard "failed" from verifyOnce → return it
 *   - schedule exhausted (72h cap) → return the last result forced to "failed"
 * "pending"/"propagating" keep polling. Uses only injected sleep + now.
 */
export async function pollUntil(
  domain: string,
  expected: readonly DnsRecord[],
  resolver: Resolver,
  deps: PollDeps,
): Promise<VerifyResult> {
  const start = deps.now();
  const verifyOpts: VerifyOptions = {
    endpoints: deps.endpoints,
    authoritativeConfirmed: deps.authoritativeConfirmed,
    dnssec: deps.dnssec,
  };

  for (;;) {
    const result = await verifyOnce(domain, expected, resolver, verifyOpts);
    const stamped: VerifyResult =
      deps.jobId === undefined ? result : { ...result, jobId: deps.jobId };

    if (
      stamped.status === "published" ||
      stamped.status === "confirmed" ||
      stamped.status === "failed"
    ) {
      return stamped;
    }

    const elapsed = deps.now() - start;
    const delay = nextDelayMs(elapsed);
    if (delay === null) {
      return { ...stamped, status: "failed" };
    }
    await deps.sleep(delay);
  }
}
