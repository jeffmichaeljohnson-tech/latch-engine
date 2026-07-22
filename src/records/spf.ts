// Latch — SPF (TXT) generation: MERGE, never clobber.
//
// A second `v=spf1` TXT at the apex is an RFC 7208 permerror — ALL mail fails.
// So we parse any existing SPF and fold new mechanisms into ONE record, preserving
// the operator's `all` qualifier and staying under the 10 DNS-lookup limit.
// Pure: the caller supplies the apex TXT set; nothing here queries DNS.

import type { ConnectWarning, DnsRecord } from "../types";
import { clampTtl } from "./vars";

/** A parsed SPF record: its mechanism/modifier terms and its (single) `all` term. */
export interface ParsedSpf {
  terms: string[];
  /** The `all` term verbatim (e.g. "~all", "-all") or null if absent. */
  all: string | null;
}

export interface SpfMergeInput {
  /** Every TXT string present at the apex; the one starting `v=spf1` is merged. */
  existingTxt?: string[];
  /** Mechanisms/includes to add — bare tokens ("include:x", "ip4:1.2.3.4") or a full "v=spf1 …" string. */
  additions: string[];
  ttl?: number;
}

export interface SpfMergeResult {
  /** The single merged SPF record string. */
  record: string;
  /** Convenience: the merged record as a canonical DnsRecord at the apex. */
  dnsRecord: DnsRecord;
  /** DNS-querying term count (include/a/mx/ptr/exists/redirect) after merge. */
  lookupCount: number;
  warnings: ConnectWarning[];
}

const ALL_RE = /^[-~?+]?all$/i;

/** Pick the `v=spf1` record out of an apex TXT set (ignores verification tokens etc.). */
export function findSpfRecord(txts: string[]): string | undefined {
  return txts.find((t) => /^v=spf1(\s|$)/i.test(t.trim()));
}

/** Parse a single SPF record into its terms and its `all` qualifier. */
export function parseSpf(txt: string): ParsedSpf {
  const tokens = txt.trim().split(/\s+/);
  const rest = tokens[0]?.toLowerCase() === "v=spf1" ? tokens.slice(1) : tokens;
  const terms: string[] = [];
  let all: string | null = null;
  for (const t of rest) {
    if (t === "") continue;
    if (ALL_RE.test(t)) {
      all = t; // one `all` wins; a well-formed record has exactly one
    } else {
      terms.push(t);
    }
  }
  return { terms, all };
}

/**
 * Count DNS-querying terms against the RFC 7208 §4.6.4 limit of 10.
 * include/a/mx/ptr/exists/redirect each cost one lookup; ip4/ip6/all cost nothing.
 */
export function countSpfLookups(terms: string[]): number {
  let n = 0;
  for (const t of terms) {
    const lower = t.toLowerCase();
    if (/^[-~?+]?(include:|exists:)/.test(lower)) n++;
    else if (/^redirect=/.test(lower)) n++;
    else if (/^[-~?+]?(a|mx|ptr)([:/]|$)/.test(lower)) n++;
  }
  return n;
}

/** Flatten additions into bare tokens, dropping any embedded `v=spf1` prefix. */
function tokenizeAdditions(additions: string[]): string[] {
  const out: string[] = [];
  for (const raw of additions) {
    for (const tok of raw.trim().split(/\s+/)) {
      if (tok === "" || tok.toLowerCase() === "v=spf1") continue;
      out.push(tok);
    }
  }
  return out;
}

/**
 * Merge new mechanisms into a single SPF record.
 * - Never emits a second `v=spf1` (permerror avoidance).
 * - Preserves the existing `all` qualifier (does NOT upgrade ~all -> -all).
 * - Dedupes includes/mechanisms case-insensitively.
 * - Flags `spf_lookup_limit` when the merged record exceeds 10 DNS lookups.
 */
export function mergeSpf(input: SpfMergeInput): SpfMergeResult {
  const warnings: ConnectWarning[] = [];
  const existing = findSpfRecord(input.existingTxt ?? []);

  let terms: string[] = [];
  let all: string | null = null;
  if (existing !== undefined) {
    warnings.push({
      code: "existing_spf",
      detail: `Merged into the existing SPF record instead of adding a second (a second v=spf1 is a permerror): ${existing.trim()}`,
    });
    const parsed = parseSpf(existing);
    terms = parsed.terms;
    all = parsed.all;
  }

  for (const add of tokenizeAdditions(input.additions)) {
    if (ALL_RE.test(add)) {
      // Preserve the operator's existing `all`; only adopt an incoming one when none is set.
      if (all === null) all = add;
      continue;
    }
    if (terms.some((t) => t.toLowerCase() === add.toLowerCase())) continue; // dedupe
    terms.push(add);
  }

  // Novice-safe default: softfail, never a bare/hard fail on a first write.
  if (all === null) all = "~all";

  const lookupCount = countSpfLookups(terms);
  if (lookupCount > 10) {
    warnings.push({
      code: "spf_lookup_limit",
      detail: `The merged SPF record needs ${lookupCount} DNS lookups; RFC 7208 caps it at 10. Flatten includes to ip4/ip6 or remove mechanisms.`,
    });
  }

  const record = ["v=spf1", ...terms, all].join(" ");
  const dnsRecord: DnsRecord = {
    type: "TXT",
    host: "@",
    value: record,
    ttl: clampTtl(input.ttl),
    purpose: "spf",
  };
  return { record, dnsRecord, lookupCount, warnings };
}
