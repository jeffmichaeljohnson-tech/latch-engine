// Latch — record planning: turn a high-level email/site intent into a prepared,
// merge-safe DnsRecord[] by applying the records/ intelligence against the zone's
// CURRENT records (read authoritatively upstream in connect()).
//
// P0-2 (Fable): the email identity defaults to a dedicated SUBDOMAIN
// (agent.theircompany.com), which structurally avoids the apex MX-clobber — the
// user's live inbound mail (Google/365 at the apex) is never touched. Apex is an
// explicit, warned choice the caller makes by passing subdomain "" / "@".

import type { ConnectWarning, DnsRecord } from "../types";
import {
  buildDkim,
  buildMx,
  dkimHost,
  mergeDmarc,
  mergeSpf,
  normalizeFqdn,
  planApex,
  type DkimTemplate,
  type DmarcTags,
  type MxEntry,
} from "../records";

export interface PlanResult {
  records: DnsRecord[];
  warnings: ConnectWarning[];
}

// ---------------------------------------------------------------------------
// host helpers
// ---------------------------------------------------------------------------

/** Canonicalize a host label for equality (lowercase, no trailing dot). */
function canonHost(host: string): string {
  return host.trim().replace(/\.$/, "").toLowerCase();
}

/** Normalize a subdomain to a bare label ("" = apex). Accepts "@"/""/"agent"/".agent.". */
function normalizeSub(sub?: string): string {
  const s = (sub ?? "").trim().replace(/^\.+|\.+$/g, "").toLowerCase();
  return s === "@" ? "" : s;
}

/** The owner name for a leaf under an optional subdomain. leaf "@"/"" collapses to the sub (or apex). */
function ownerFor(leaf: string, sub: string): string {
  const base = leaf === "@" || leaf === "" ? "" : leaf;
  if (sub === "") return base === "" ? "@" : base;
  return base === "" ? sub : `${base}.${sub}`;
}

function withHost(record: DnsRecord, host: string): DnsRecord {
  return { ...record, host };
}

/** All TXT values at a host (for SPF/DMARC merge). */
function txtAt(existing: DnsRecord[], host: string): string[] {
  const h = canonHost(host);
  return existing.filter((r) => r.type === "TXT" && canonHost(r.host) === h).map((r) => r.value);
}

/** MX targets at a host (trailing-dot stripped) — feeds the clobber-guard. */
function mxTargetsAt(existing: DnsRecord[], host: string): string[] {
  const h = canonHost(host);
  return existing
    .filter((r) => r.type === "MX" && canonHost(r.host) === h)
    .map((r) => r.value.trim().replace(/\.$/, ""))
    .filter((v) => v.length > 0 && v !== ".");
}

/** Record types present at a host (for the DKIM CNAME-coexistence guard). */
function typesAt(existing: DnsRecord[], host: string): DnsRecord["type"][] {
  const h = canonHost(host);
  return existing.filter((r) => canonHost(r.host) === h).map((r) => r.type);
}

// ---------------------------------------------------------------------------
// email
// ---------------------------------------------------------------------------

export interface EmailPlan {
  /**
   * Subdomain hosting the identity (RECOMMENDED — avoids the apex MX clobber).
   * "" or "@" writes at the apex (explicit, warned).
   */
  subdomain?: string;
  /** SPF include tokens to fold into the (single) SPF record, e.g. "include:_spf.resend.com". */
  spfIncludes: string[];
  /** MX entries. OMIT for a send-only identity (no inbound → no MX, nothing to clobber). */
  mx?: MxEntry[];
  /** Provider-supplied DKIM templates (CNAME vs TXT is authoritative from the provider). */
  dkim?: DkimTemplate[];
  /** DMARC tags; defaults to p=none (monitor-only). */
  dmarcTags?: DmarcTags;
  ttl?: number;
}

/**
 * Build the email DNS record set, merge-safe against `existing`:
 * SPF single-record merge · MX clobber-guard (only when MX requested) · DKIM
 * chunk/coexistence · DMARC p=none merge. All hosted under the chosen subdomain.
 */
export function planEmailRecords(plan: EmailPlan, existing: DnsRecord[]): PlanResult {
  const sub = normalizeSub(plan.subdomain);
  const warnings: ConnectWarning[] = [];
  const records: DnsRecord[] = [];

  // SPF — one record at the identity host.
  const spfHost = ownerFor("@", sub);
  const spf = mergeSpf({
    existingTxt: txtAt(existing, spfHost),
    additions: plan.spfIncludes,
    ttl: plan.ttl,
  });
  records.push(withHost(spf.dnsRecord, spfHost));
  warnings.push(...spf.warnings);

  // MX — only if the identity receives mail. Guarded against clobbering a live provider.
  if (plan.mx && plan.mx.length > 0) {
    const mxHost = ownerFor("@", sub);
    const mx = buildMx({
      entries: plan.mx,
      existingMx: mxTargetsAt(existing, mxHost),
      host: mxHost,
      ttl: plan.ttl,
    });
    records.push(...mx.records);
    warnings.push(...mx.warnings);
  }

  // DKIM — provider-specified; chunked; coexistence-guarded at its selector label.
  for (const template of plan.dkim ?? []) {
    const host = ownerFor(dkimHost(template.selector), sub);
    const built = buildDkim({
      ...template,
      existingTypesAtLabel: typesAt(existing, host),
    });
    records.push(withHost(built.record, host));
  }

  // DMARC — p=none default, merged into any existing policy.
  const dmarcHost = ownerFor("_dmarc", sub);
  const existingDmarc = txtAt(existing, dmarcHost).find((t) => /^v=DMARC1/i.test(t.trim()));
  const dmarc = mergeDmarc({
    ...(existingDmarc !== undefined ? { existingTxt: existingDmarc } : {}),
    ...(plan.dmarcTags !== undefined ? { tags: plan.dmarcTags } : {}),
    ...(plan.ttl !== undefined ? { ttl: plan.ttl } : {}),
  });
  records.push(withHost(dmarc.record, dmarcHost));
  warnings.push(...dmarc.warnings);

  return { records, warnings };
}

// ---------------------------------------------------------------------------
// site (point a domain at a published site)
// ---------------------------------------------------------------------------

export interface SitePlan {
  /** Subdomain to point ("" / "@" = apex). */
  subdomain?: string;
  /** The hostname the domain should point at (e.g. the Pages/publish host). */
  target: string;
  /** Whether the DNS host offers ALIAS/flattening at the apex (from adapter capabilities). */
  supportsApex: boolean;
  /** Resolved A/AAAA for the flatten fallback when the host has no apex ALIAS. */
  resolved?: { a?: string[]; aaaa?: string[] };
  ttl?: number;
}

/**
 * Build site records:
 * - subdomain      → a plain CNAME to the target.
 * - apex + flatten → a CNAME at "@" (the flattening host, e.g. Cloudflare, resolves it).
 * - apex, no flat  → A/AAAA from resolved IPs; if none supplied, a warning + no records
 *   (the caller must resolve the target first — we never write a literal apex CNAME).
 */
export function planSiteRecords(plan: SitePlan, _existing: DnsRecord[]): PlanResult {
  const sub = normalizeSub(plan.subdomain);
  const ttl = plan.ttl;

  if (sub !== "") {
    return {
      records: [
        { type: "CNAME", host: sub, value: normalizeFqdn(plan.target), ttl: ttl ?? 3600, purpose: "site" },
      ],
      warnings: [],
    };
  }

  // Apex.
  if (plan.supportsApex) {
    // A flattening host accepts a CNAME at the apex and serves A/AAAA for it.
    return {
      records: [
        { type: "CNAME", host: "@", value: normalizeFqdn(plan.target), ttl: ttl ?? 3600, purpose: "site" },
      ],
      warnings: [],
    };
  }

  const apex = planApex({
    supportsApex: false,
    target: plan.target,
    ...(plan.resolved !== undefined ? { resolved: plan.resolved } : {}),
    ...(ttl !== undefined ? { ttl } : {}),
  });
  if (apex.strategy === "flatten") {
    return { records: apex.records, warnings: [] };
  }
  return {
    records: [],
    warnings: [{ code: "apex_cname", detail: apex.strategy === "unresolved" ? apex.reason : "apex" }],
  };
}
