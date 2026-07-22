// Latch — MX record generation. The #1 silent email failure.
//
// ANY existing MX means a live mail provider already receives mail — connect()
// must warn (existing_mx) and never silently clobber it. We enforce unique
// priorities, normalize targets to trailing-dot FQDNs, and honor null-MX. Pure.

import type { ConnectWarning, DnsRecord } from "../types";
import { LatchError } from "../types";
import { clampTtl, normalizeFqdn } from "./vars";

export interface MxEntry {
  /** Preference value; must be unique across the set. */
  priority: number;
  /** Mail exchanger hostname; normalized to a trailing-dot FQDN. */
  target: string;
}

export interface MxBuildInput {
  entries: MxEntry[];
  /** Incumbent MX targets (from DetectResult.existingMx). Non-empty => existing_mx warning. */
  existingMx?: string[];
  /** Owner name for the records; defaults to the apex "@". */
  host?: string;
  ttl?: number;
  /** Emit the RFC 7505 null-MX ("0 .") — this domain sends but never receives mail. */
  nullMx?: boolean;
}

export interface MxBuildResult {
  records: DnsRecord[];
  warnings: ConnectWarning[];
}

/**
 * Build MX records.
 * - existingMx non-empty => existing_mx warning naming the incumbent targets
 *   (the caller/UI must hard-stop for explicit confirm; we never drop them here).
 * - nullMx => a single "0 ." record (RFC 7505); entries are ignored.
 * - duplicate priorities => LatchError (a resolver picks nondeterministically).
 */
export function buildMx(input: MxBuildInput): MxBuildResult {
  const warnings: ConnectWarning[] = [];
  const host = input.host ?? "@";
  const ttl = clampTtl(input.ttl);
  const existing = input.existingMx ?? [];

  if (existing.length > 0) {
    warnings.push({
      code: "existing_mx",
      detail: `This domain already receives mail via: ${existing.join(", ")}. Confirm before replacing its MX records.`,
    });
  }

  if (input.nullMx) {
    // RFC 7505: preference 0, target "." — an explicit "no mail delivered here".
    return {
      records: [{ type: "MX", host, value: ".", ttl, priority: 0, purpose: "mx" }],
      warnings,
    };
  }

  const priorities = new Set<number>();
  const records: DnsRecord[] = [];
  for (const entry of input.entries) {
    if (priorities.has(entry.priority)) {
      throw new LatchError(
        "provider_rejected",
        `Duplicate MX priority ${entry.priority}: each MX must have a unique preference.`,
      );
    }
    priorities.add(entry.priority);
    records.push({
      type: "MX",
      host,
      value: normalizeFqdn(entry.target),
      ttl,
      priority: entry.priority,
      purpose: "mx",
    });
  }
  return { records, warnings };
}
