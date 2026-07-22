// Latch — DMARC (_dmarc TXT) generation.
//
// A new record defaults to p=none (monitor-only) — never quarantine/reject a
// novice on day one. Merging into an existing _dmarc PRESERVES the operator's
// tags (p/rua/ruf/pct/…); incoming tags only fill gaps, never clobber. Pure.

import type { ConnectWarning, DnsRecord } from "../types";
import { clampTtl } from "./vars";

/** DMARC tag bag. Values are strings on the wire (pct=… is still "5", not 5). */
export type DmarcTags = Record<string, string>;

export interface DmarcMergeInput {
  /** The existing `_dmarc` TXT string, if the domain already has one. */
  existingTxt?: string;
  /** Tags to set on a new record / fill into gaps of an existing one. */
  tags?: DmarcTags;
  ttl?: number;
}

export interface DmarcResult {
  record: DnsRecord;
  warnings: ConnectWarning[];
}

/** Stable emission order; unknown tags follow in insertion order. */
const TAG_ORDER = ["v", "p", "sp", "rua", "ruf", "pct", "adkim", "aspf", "fo", "rf", "ri"];

function isDmarc(txt: string): boolean {
  return /^v=DMARC1/i.test(txt.trim());
}

/** Parse a `_dmarc` TXT into a lowercase-keyed tag map. */
export function parseDmarc(txt: string): DmarcTags {
  const out: DmarcTags = {};
  for (const seg of txt.split(";")) {
    const s = seg.trim();
    if (s === "") continue;
    const eq = s.indexOf("=");
    if (eq === -1) continue;
    const k = s.slice(0, eq).trim().toLowerCase();
    const v = s.slice(eq + 1).trim();
    if (k !== "") out[k] = v;
  }
  return out;
}

/** Serialize a tag map into a DMARC TXT value with v= first and p= second. */
export function serializeDmarc(tags: DmarcTags): string {
  const seen = new Set<string>();
  const parts: string[] = [];
  for (const k of TAG_ORDER) {
    const v = tags[k];
    if (v !== undefined) {
      parts.push(`${k}=${v}`);
      seen.add(k);
    }
  }
  for (const [k, v] of Object.entries(tags)) {
    if (!seen.has(k)) parts.push(`${k}=${v}`);
  }
  return parts.join("; ");
}

/**
 * Build or merge a DMARC record.
 * - No existing record: emit v=DMARC1 with p=none default plus supplied tags.
 * - Existing record: PRESERVE its tags (they win); supplied tags fill only gaps.
 */
export function mergeDmarc(input: DmarcMergeInput = {}): DmarcResult {
  const warnings: ConnectWarning[] = [];

  const merged: DmarcTags = { v: "DMARC1", p: "none" };
  if (input.tags) {
    for (const [k, v] of Object.entries(input.tags)) merged[k.toLowerCase()] = v;
  }

  if (input.existingTxt !== undefined && isDmarc(input.existingTxt)) {
    warnings.push({
      code: "existing_dmarc",
      detail: `Preserved the existing DMARC policy; new tags filled only unset gaps: ${input.existingTxt.trim()}`,
    });
    // Existing tags applied last => they win (never clobbered).
    for (const [k, v] of Object.entries(parseDmarc(input.existingTxt))) merged[k] = v;
  }

  const record: DnsRecord = {
    type: "TXT",
    host: "_dmarc",
    value: serializeDmarc(merged),
    ttl: clampTtl(input.ttl),
    purpose: "dmarc",
  };
  return { record, warnings };
}

/** Build a fresh DMARC record (p=none default). Thin wrapper over mergeDmarc. */
export function buildDmarc(tags?: DmarcTags, ttl?: number): DmarcResult {
  return mergeDmarc({ tags, ttl });
}
