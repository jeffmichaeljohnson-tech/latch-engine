// Latch — the connect() orchestrator: the keystone that ties detect → read-existing
// → plan → dispatch into one flow, and NEVER dead-ends (an unwritable path always
// degrades to a polished manual fallback with the prepared records).
//
// Read-before-write: the SPF/DMARC merges and the MX clobber-guard run
// against the zone's CURRENT records, read AUTHORITATIVELY through the same adapter
// that will write (CF-API read-back), never a stale public-DoH cache. When no
// adapter can read (manual path), a DoH read is the best-effort fallback.
//
// Method scoping: a "cloudflare" detection is only WRITTEN via our CF
// token when the zone is confirmed present in OUR account; a user-owned CF zone
// falls back to manual. Control proof (P0-4) is recorded for every write.

import type {
  Adapter,
  AdapterAuth,
  ConnectResult,
  ConnectWarning,
  ControlProof,
  DetectResult,
  DnsRecord,
  ManualRecord,
} from "../types";
import { LatchError } from "../types";
import { makeDomainConnectAdapter, type DomainConnectConfig } from "../providers";
import { V1_COVERAGE, adapterIdOf, type CoveragePolicy } from "./coverage";
import {
  planEmailRecords,
  planFromResolvedRecords,
  planSiteRecords,
  type EmailPlan,
  type PlanResult,
  type SitePlan,
} from "./plan";

export interface ConnectDeps {
  /** Adapter registry lookup (records/detect-independent). */
  getAdapter: (id: string) => Adapter | undefined;
  /** Per-adapter credential bag (resolved at the boundary — secrets never in the engine). */
  adapterAuth?: (id: string) => AdapterAuth | undefined;
  /** Confirm the domain's zone is in OUR Cloudflare account; returns our { zoneId, token } or null. */
  resolveOwnedCloudflareZone?: (domain: string) => Promise<AdapterAuth | null>;
  /** Best-effort existing-record read over DoH when no adapter can read (manual path). */
  readExistingViaDns?: (domain: string) => Promise<DnsRecord[]>;
  /** Redirect URI for the Domain Connect sync flow. */
  redirectUri?: string;
  /** Build a Domain Connect config from detect() + the prepared records (caller maps template vars). */
  domainConnectConfig?: (detect: DetectResult, records: DnsRecord[]) => DomainConnectConfig | null;
  /** Job id generator (injected — no Math.random in the engine). */
  newJobId: () => string;
  /** v1 coverage policy (defaults to V1_COVERAGE). */
  coverage?: CoveragePolicy;
}

export interface ConnectInput {
  /** Result of a prior detect() call. */
  detect: DetectResult;
  /** Build an email identity's records (SPF/MX/DKIM/DMARC) — the first consumer. */
  email?: EmailPlan;
  /** Point the domain at a published site (A/CNAME). */
  site?: SitePlan;
  /** Escape hatch: a finished record set the caller prepared itself. */
  records?: DnsRecord[];
  /** A control proof the caller already established (e.g. a completed TXT challenge). */
  controlProof?: ControlProof;
}

type Path =
  | { kind: "cloudflare"; auth: AdapterAuth; proof: ControlProof }
  | { kind: "domain_connect"; proof: ControlProof }
  | { kind: "adapter"; adapterId: string; auth: AdapterAuth | undefined; proof: ControlProof }
  | { kind: "manual"; reason: string };

async function resolvePath(
  detect: DetectResult,
  coverage: CoveragePolicy,
  deps: ConnectDeps,
): Promise<Path> {
  // Ownership WINS over the detected method: if the zone is in OUR CF account we
  // write directly via the CF adapter regardless of what detect() surfaced (a
  // CF-hosted zone advertises _domainconnect, so detect may say domain_connect —
  // but for a zone we manage we need no user consent). Checked first so an owned
  // zone never falls to manual just because DC discovery happened to succeed.
  if (coverage.cloudflare && deps.resolveOwnedCloudflareZone) {
    const auth = await deps.resolveOwnedCloudflareZone(detect.domain);
    if (auth) return { kind: "cloudflare", auth, proof: { kind: "cf_account_owned" } };
  }

  const method = detect.method;

  if (method === "cloudflare") {
    // NS is Cloudflare but the zone is NOT in our account (ownership checked above).
    return { kind: "manual", reason: "Cloudflare-hosted but not in this account" };
  }

  if (method === "domain_connect") {
    if (!coverage.domainConnect) return { kind: "manual", reason: "Domain Connect disabled" };
    return { kind: "domain_connect", proof: { kind: "provider_consent" } };
  }

  const id = adapterIdOf(method);
  if (id) {
    const wired = (id === "route53" && coverage.route53) || (id === "namecheap" && coverage.namecheap);
    if (!wired) return { kind: "manual", reason: `${id} not wired in v1` };
    return {
      kind: "adapter",
      adapterId: id,
      auth: deps.adapterAuth?.(id),
      proof: { kind: "user_credentials" },
    };
  }

  return { kind: "manual", reason: "no automated path for this DNS host" };
}

interface CurrentRead {
  records: DnsRecord[];
  /** True when a WRITE path's authoritative read threw — the caller must not write blind. */
  authoritativeFailed: boolean;
}

/**
 * Read current records for the merges. On a write path, try the adapter's
 * AUTHORITATIVE read first and distinguish three outcomes:
 *   - records        the read succeeded → merge against them
 *   - "no-method"    the adapter can't read → fall through to best-effort DoH
 *   - "failed"       the authoritative read THREW → signal authoritativeFailed so
 *                    connect() degrades to manual instead of writing against a
 *                    stale/[] view (a transient CF read failure must not clobber MX).
 */
async function readCurrent(path: Path, domain: string, deps: ConnectDeps): Promise<CurrentRead> {
  const viaAdapter = async (
    id: string,
    auth: AdapterAuth | undefined,
  ): Promise<DnsRecord[] | "no-method" | "failed"> => {
    const adapter = deps.getAdapter(id);
    if (!adapter?.readExisting) return "no-method";
    try {
      return await adapter.readExisting(domain, auth);
    } catch {
      return "failed";
    }
  };

  if (path.kind === "cloudflare" || path.kind === "adapter") {
    const id = path.kind === "cloudflare" ? "cloudflare" : path.adapterId;
    const r = await viaAdapter(id, path.auth);
    if (r === "failed") return { records: [], authoritativeFailed: true };
    if (r !== "no-method") return { records: r, authoritativeFailed: false };
    // no readExisting → fall through to best-effort DoH
  }

  if (deps.readExistingViaDns) {
    try {
      return { records: await deps.readExistingViaDns(domain), authoritativeFailed: false };
    } catch {
      return { records: [], authoritativeFailed: false };
    }
  }
  return { records: [], authoritativeFailed: false };
}

function buildRecords(input: ConnectInput, existing: DnsRecord[]): PlanResult {
  if (input.email) return planEmailRecords(input.email, existing);
  if (input.site) return planSiteRecords(input.site, existing);
  // Caller-supplied RESOLVED records (e.g. agent-email's Resend set): classify + guard
  // (SPF merge / MX clobber-guard) against existing DNS — never write them raw.
  if (input.records) return planFromResolvedRecords(input.records, existing);
  return { records: [], warnings: [] };
}

function manualResult(
  domain: string,
  records: DnsRecord[],
  jobId: string,
  warnings: ConnectWarning[],
  reason: string,
): ConnectResult {
  return {
    domain,
    status: "manual_fallback",
    applied: [],
    manual: records.map((r): ManualRecord => ({ ...r })),
    jobId,
    warnings: [...warnings, { code: "manual_fallback", detail: reason }],
  };
}

export async function connect(input: ConnectInput, deps: ConnectDeps): Promise<ConnectResult> {
  const coverage = deps.coverage ?? V1_COVERAGE;
  const domain = input.detect.domain;
  const jobId = deps.newJobId();

  const path = await resolvePath(input.detect, coverage, deps);
  const current = await readCurrent(path, domain, deps);
  const plan = buildRecords(input, current.records);
  const warnings = [...plan.warnings];
  const records = plan.records;

  // Never dead-end.
  if (path.kind === "manual") {
    return manualResult(domain, records, jobId, warnings, path.reason);
  }

  // A write path whose authoritative read failed: do NOT write against an unknown
  // zone state (the SPF/DMARC merge + MX clobber-guard would be blind). Degrade to
  // manual with the planned records so the user can add them safely.
  if (current.authoritativeFailed) {
    return manualResult(
      domain,
      records,
      jobId,
      [
        ...warnings,
        {
          code: "provider_error",
          detail: "Could not read your current DNS to merge safely — add the records manually.",
        },
      ],
      "authoritative read failed",
    );
  }

  const controlProof = input.controlProof ?? path.proof;

  if (path.kind === "domain_connect") {
    const config = deps.domainConnectConfig?.(input.detect, records) ?? null;
    if (config) {
      const adapter = makeDomainConnectAdapter(config);
      const url = await adapter.authUrl(domain, deps.redirectUri ?? "");
      if (url) {
        return {
          domain,
          status: "oauth_required",
          applied: [],
          manual: [],
          jobId,
          authUrl: url,
          controlProof,
          warnings,
        };
      }
    }
    // No settings/URL — show the records to add by hand instead of stranding the user.
    return manualResult(domain, records, jobId, warnings, "Domain Connect settings unavailable");
  }

  // cloudflare | adapter → write through the adapter.
  const adapterId = path.kind === "cloudflare" ? "cloudflare" : path.adapterId;
  const auth = path.auth;
  const adapter = deps.getAdapter(adapterId);
  if (!adapter) {
    return manualResult(domain, records, jobId, warnings, `no adapter registered for ${adapterId}`);
  }

  try {
    const { applied, manual } = await adapter.apply(domain, records, auth);
    if (applied.length === 0) {
      return {
        domain,
        status: "manual_fallback",
        applied,
        manual: manual.length > 0 ? manual : records.map((r): ManualRecord => ({ ...r })),
        jobId,
        controlProof,
        warnings,
      };
    }
    return { domain, status: "applied", applied, manual, jobId, controlProof, warnings };
  } catch (e) {
    // A provider hard-failure must not strand the user — degrade to manual fallback.
    const detail = e instanceof LatchError ? e.message : "provider write failed";
    return manualResult(
      domain,
      records,
      jobId,
      [...warnings, { code: "provider_error", detail }],
      detail,
    );
  }
}
