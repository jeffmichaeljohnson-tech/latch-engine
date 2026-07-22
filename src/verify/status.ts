// Latch — two-tier propagation status.
//
// Pure status computation. Given, per expected record, how many DoH resolvers
// confirmed the value (and whether an authoritative CF-API read-back confirmed
// it), decide a VerifyStatus; then roll per-record states up to one overall
// status.
//
// The two-tier truth (see types.ts VerifyStatus):
//   - "published"   the authoritative-style signal confirms — the REAL success
//                   gate. For an owned CF zone the caller passes
//                   `authoritativeConfirmed` (a CF-API read-back) and it wins:
//                   published requires that authoritative signal AND public
//                   resolvers having caught up.
//   - "propagating" authoritative confirms (or, on an external zone, SOME public
//                   resolvers confirm) but other public resolvers are still
//                   serving stale/absent answers.
//   - "pending"     nothing confirms yet.
//   - "failed"      a hard error (every queried resolver errored, with no
//                   authoritative fallback).
//
// Why the authoritative flag matters: public DoH endpoints answer *recursively*
// from their own cache, NOT from the zone's authoritative nameservers. So public
// DoH is only a propagation signal. For a zone we own, the CF-API read-back is
// ground truth and overrides the recursive public view.

import type { RecordVerifyState, VerifyStatus } from "../types";

/**
 * The observed signal for one expected record, distilled from querying the DoH
 * endpoints (and, for owned zones, an authoritative read-back).
 */
export interface RecordObservation {
  /** DoH endpoints that returned the expected value. */
  confirmed: number;
  /** DoH endpoints that answered cleanly (matched or not) — excludes hard errors. */
  total: number;
  /** DoH endpoints that hard-errored (network/HTTP failure, not NXDOMAIN). */
  errors: number;
  /**
   * Owned-zone authoritative read-back:
   *   true      authoritative source confirms the record (the real success gate);
   *   false     authoritative checked and the record is not present yet;
   *   undefined external zone / no authoritative signal — fall back to DoH consensus.
   */
  authoritativeConfirmed?: boolean;
}

/** Decide the status of a single record from its observed signal. */
export function recordStatus(obs: RecordObservation): VerifyStatus {
  const { confirmed, total, errors, authoritativeConfirmed } = obs;

  // Owned zone: the authoritative read-back is ground truth and wins.
  if (authoritativeConfirmed === true) {
    // Real success only once public resolvers have also caught up; until then it
    // is authoritatively-written-but-propagating.
    return total > 0 && confirmed >= total ? "published" : "propagating";
  }
  if (authoritativeConfirmed === false) {
    // Authoritative says the record is not there yet. A public resolver seeing it
    // early is noise against the success gate, but signals movement.
    return confirmed > 0 ? "propagating" : "pending";
  }

  // External zone: public DoH consensus is the best available signal — but it is
  // RECURSIVE (cache), not authoritative, so it can never earn the strong "published"
  // gate. Full agreement is the terminal "confirmed" success; partial is "propagating".
  if (total === 0) {
    // No clean answers at all. If every queried resolver hard-errored, that is a
    // hard failure; otherwise nothing was queried → pending.
    return errors > 0 ? "failed" : "pending";
  }
  if (confirmed >= total) return "confirmed";
  if (confirmed > 0) return "propagating";
  return "pending";
}

/**
 * Roll per-record states up to one overall status.
 *  - any "failed"                       → "failed"     (a hard error dominates)
 *  - all "published"                    → "published"  (strong authoritative gate)
 *  - all terminal-success (published or
 *    "confirmed", at least one weaker)  → "confirmed"  (the weakest terminal wins — honest)
 *  - all "pending"                      → "pending"
 *  - otherwise (mixed / any propagating)→ "propagating"
 */
export function rollupStatus(records: readonly RecordVerifyState[]): VerifyStatus {
  if (records.length === 0) return "pending";
  if (records.some((r) => r.status === "failed")) return "failed";
  if (records.every((r) => r.status === "published")) return "published";
  if (records.every((r) => r.status === "published" || r.status === "confirmed")) {
    return "confirmed";
  }
  if (records.every((r) => r.status === "pending")) return "pending";
  return "propagating";
}
