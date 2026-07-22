// Latch — dynamic variable resolution + shared record utilities.
//
// Records arrive as templates whose host/value may embed uppercase, case-sensitive
// variables ({DOMAIN}{SUBDOMAIN}{SLD}{TLD}{emailProviderSPF}) — the Entri-parity
// SDK contract. The engine resolves them here, once, before a record is written.
// Pure: no network, no clock; the caller supplies every value.

import type { DnsRecord, RecordVars } from "../types";

// ---------------------------------------------------------------------------
// email provider -> SPF include token
// ---------------------------------------------------------------------------

/**
 * Sending-provider aliases -> the `include:` mechanism to add to SPF.
 * Keys are matched case-insensitively after trimming. Values are full
 * `include:` tokens so they drop straight into an SPF term list.
 */
export const EMAIL_PROVIDER_SPF: Readonly<Record<string, string>> = {
  google: "include:_spf.google.com",
  "google-workspace": "include:_spf.google.com",
  googleworkspace: "include:_spf.google.com",
  gsuite: "include:_spf.google.com",
  gmail: "include:_spf.google.com",
  microsoft: "include:spf.protection.outlook.com",
  microsoft365: "include:spf.protection.outlook.com",
  "365": "include:spf.protection.outlook.com",
  o365: "include:spf.protection.outlook.com",
  office365: "include:spf.protection.outlook.com",
  outlook: "include:spf.protection.outlook.com",
  zoho: "include:zoho.com",
  sendgrid: "include:sendgrid.net",
  mailgun: "include:mailgun.org",
  amazonses: "include:amazonses.com",
  ses: "include:amazonses.com",
  mailchimp: "include:servers.mcsv.net",
  mandrill: "include:spf.mandrillapp.com",
  postmark: "include:spf.mtasv.net",
  resend: "include:_spf.resend.com",
};

/** Resolve a provider name/alias to its SPF include token, or undefined if unknown. */
export function emailProviderSpfInclude(provider: string): string | undefined {
  return EMAIL_PROVIDER_SPF[provider.trim().toLowerCase()];
}

// ---------------------------------------------------------------------------
// SLD / TLD split (pragmatic public-suffix awareness)
// ---------------------------------------------------------------------------

/**
 * KNOWN LIMITATION (flagged for red-team): this is NOT a full Public Suffix List.
 * A correct SLD/TLD split needs the PSL (thousands of rules, updated regularly),
 * which we deliberately do not vendor into the zero-dependency engine. Instead we
 * carry a small set of the common multi-part suffixes so `example.co.uk` splits to
 * SLD=example / TLD=co.uk instead of the wrong SLD=co / TLD=uk. Domains under a
 * multi-part suffix NOT in this set will mis-split. Callers that need exact PSL
 * behavior must pass SLD/TLD explicitly rather than relying on deriveVars().
 */
export const MULTI_PART_SUFFIXES: ReadonlySet<string> = new Set([
  // United Kingdom
  "co.uk",
  "org.uk",
  "me.uk",
  "ltd.uk",
  "plc.uk",
  "net.uk",
  "sch.uk",
  "ac.uk",
  "gov.uk",
  // Australia
  "com.au",
  "net.au",
  "org.au",
  "edu.au",
  "gov.au",
  "id.au",
  // Japan
  "co.jp",
  "or.jp",
  "ne.jp",
  "ac.jp",
  "go.jp",
  // New Zealand
  "co.nz",
  "net.nz",
  "org.nz",
  // Others in common use
  "co.za",
  "com.br",
  "com.cn",
  "com.mx",
  "co.in",
]);

/** Strip a single trailing dot and lowercase. */
function canon(domain: string): string {
  return domain.trim().replace(/\.$/, "").toLowerCase();
}

/**
 * Split a registrable domain into { sld, tld } using the pragmatic multi-part
 * suffix set above. See MULTI_PART_SUFFIXES for the known limitation.
 */
export function splitSldTld(domain: string): { sld: string; tld: string } {
  const labels = canon(domain).split(".").filter((l) => l.length > 0);
  if (labels.length === 0) return { sld: "", tld: "" };
  if (labels.length === 1) return { sld: labels[0] ?? "", tld: "" };

  if (labels.length >= 3) {
    const lastTwo = labels.slice(-2).join(".");
    if (MULTI_PART_SUFFIXES.has(lastTwo)) {
      return { sld: labels[labels.length - 3] ?? "", tld: lastTwo };
    }
  }
  return {
    sld: labels[labels.length - 2] ?? "",
    tld: labels[labels.length - 1] ?? "",
  };
}

// ---------------------------------------------------------------------------
// generic record utilities (shared by the sibling record builders)
// ---------------------------------------------------------------------------

/** The contract floor for TTL (types.ts: "Minimum 300 (enforced by the engine)"). */
export const MIN_TTL = 300;

/** Clamp a caller TTL to the contract floor; apply a fallback when unset. */
export function clampTtl(ttl: number | undefined, fallback = 3600): number {
  const t = ttl ?? fallback;
  return t < MIN_TTL ? MIN_TTL : t;
}

/**
 * Normalize an MX/target hostname to an absolute FQDN with a trailing dot.
 * The null-MX target "." is returned unchanged (RFC 7505).
 */
export function normalizeFqdn(target: string): string {
  const t = target.trim();
  if (t === "" || t === ".") return ".";
  return t.endsWith(".") ? t : `${t}.`;
}

// ---------------------------------------------------------------------------
// variable substitution
// ---------------------------------------------------------------------------

const VAR_RE = /\{(DOMAIN|SUBDOMAIN|SLD|TLD|emailProviderSPF)\}/g;

/** Substitute known variables in a single string. Unset vars are left verbatim. */
function applyVars(input: string, vars: RecordVars): string {
  return input.replace(VAR_RE, (match, key: string) => {
    const v = (vars as unknown as Record<string, string | undefined>)[key];
    return v === undefined ? match : v;
  });
}

/** Resolve {DOMAIN}{SUBDOMAIN}{SLD}{TLD}{emailProviderSPF} in a record's host + value. */
export function resolveVars(record: DnsRecord, vars: RecordVars): DnsRecord {
  return {
    ...record,
    host: applyVars(record.host, vars),
    value: applyVars(record.value, vars),
  };
}

/** Resolve vars across a batch of records. */
export function resolveVarsAll(records: DnsRecord[], vars: RecordVars): DnsRecord[] {
  return records.map((r) => resolveVars(r, vars));
}

/**
 * Build a RecordVars bag from a domain. SLD/TLD come from the pragmatic split
 * (known limitation above); an optional email provider resolves emailProviderSPF.
 */
export function deriveVars(
  domain: string,
  opts?: { subdomain?: string; emailProvider?: string },
): RecordVars {
  const { sld, tld } = splitSldTld(domain);
  const emailProviderSPF = opts?.emailProvider
    ? emailProviderSpfInclude(opts.emailProvider)
    : undefined;
  return {
    DOMAIN: canon(domain),
    SUBDOMAIN: opts?.subdomain ?? "",
    SLD: sld,
    TLD: tld,
    emailProviderSPF,
  };
}
