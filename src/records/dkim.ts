// Latch — DKIM record generation.
//
// CNAME-vs-TXT is PROVIDER-SPECIFIED, never guessed: Resend/SES/Mailchimp hand a
// CNAME; SendGrid/Google hand a TXT. A 2048-bit key's p= exceeds the 255-octet TXT
// string limit and must be split into multiple quoted strings inside ONE record
// (two records at one selector = broken DKIM). Pure: no network.

import type { DnsRecord } from "../types";
import { LatchError } from "../types";
import { clampTtl } from "./vars";

/** The single-TXT-character-string octet limit (RFC 1035 §3.3.14). */
export const TXT_STRING_LIMIT = 255;

/** A provider-supplied DKIM template. `recordType` is authoritative, never inferred. */
export interface DkimTemplate {
  /** The selector label, e.g. "resend", "google", "s1". */
  selector: string;
  /** Provider-specified: Resend/SES = CNAME, SendGrid/Google = TXT. */
  recordType: "CNAME" | "TXT";
  /** CNAME: the target host. TXT: the full key string ("v=DKIM1; k=rsa; p=…"). */
  value: string;
  ttl?: number;
  /**
   * Record types already present at `<selector>._domainkey` (for the RFC 1034
   * CNAME-coexistence guard). A CNAME cannot share a label with any other type.
   */
  existingTypesAtLabel?: DnsRecord["type"][];
}

export interface DkimBuildResult {
  record: DnsRecord;
}

/** Strip one layer of surrounding double-quotes if the caller pre-quoted the value. */
function unquote(value: string): string {
  const m = /^"([\s\S]*)"$/.exec(value.trim());
  return m ? (m[1] ?? "") : value.trim();
}

/**
 * Split a TXT value into <=255-octet character-strings. DKIM keys are base64
 * ASCII, so byte length equals code-unit length here (documented assumption).
 * Returns the raw chunks; buildDkim quotes and joins them into ONE record value.
 */
export function splitTxtString(value: string, limit = TXT_STRING_LIMIT): string[] {
  const raw = unquote(value);
  if (raw.length <= limit) return [raw];
  const parts: string[] = [];
  for (let i = 0; i < raw.length; i += limit) parts.push(raw.slice(i, i + limit));
  return parts;
}

/**
 * Render a TXT value as zone-file character-strings. A value over 255 octets
 * becomes multiple space-separated quoted strings that DNS concatenates back into
 * one logical value; a short value is returned verbatim (unquoted, display-safe).
 */
export function formatTxtValue(value: string): string {
  const parts = splitTxtString(value);
  if (parts.length <= 1) return parts[0] ?? "";
  return parts.map((p) => `"${p}"`).join(" ");
}

/** The owner name for a DKIM record: `<selector>._domainkey`. */
export function dkimHost(selector: string): string {
  return `${selector.trim()}._domainkey`;
}

/**
 * Build one DKIM record from a provider template. Enforces the RFC 1034
 * CNAME-coexistence rule at the selector label and chunks an over-length TXT key.
 */
export function buildDkim(template: DkimTemplate): DkimBuildResult {
  const host = dkimHost(template.selector);
  const existing = template.existingTypesAtLabel ?? [];

  // RFC 1034: a CNAME must be the ONLY record at its owner name.
  if (template.recordType === "CNAME" && existing.some((t) => t !== "CNAME")) {
    throw new LatchError(
      "unsupported",
      `Cannot place a DKIM CNAME at ${host}: the label already has ${existing.join(", ")} (RFC 1034 CNAME-coexistence).`,
    );
  }
  if (template.recordType === "TXT" && existing.includes("CNAME")) {
    throw new LatchError(
      "unsupported",
      `Cannot place a DKIM TXT at ${host}: the label already has a CNAME (RFC 1034 CNAME-coexistence).`,
    );
  }

  const value =
    template.recordType === "TXT" ? formatTxtValue(template.value) : template.value.trim();

  const record: DnsRecord = {
    type: template.recordType,
    host,
    value,
    ttl: clampTtl(template.ttl),
    purpose: "dkim",
  };
  return { record };
}
