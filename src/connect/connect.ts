// Latch — the connect() orchestrator: the keystone that ties detect → read-existing
// → plan → dispatch into one flow, and NEVER dead-ends (an unwritable path always
// degrades to a polished manual fallback with the prepared records).
//
// Read-before-write (Fable P0-1): the SPF/DMARC merges and the MX clobber-guard run
// against the zone's CURRENT records, read AUTHORITATIVELY through the same adapter
// that will write (CF-API read-back), never a stale public-DoH cache. When no
// adapter can read (manual path), a DoH read is the best-effort fallback.
//
// Method scoping (Fable P0-3): a "cloudflare" detection is only WRITTEN via our CF
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
  const method = detect.method;

  if (method === "cloudflare") {
    if (!coverage.cloudflare) return { kind: "manual", reason: "Cloudflare path disabled" };
    const auth = deps.resolveOwnedCloudflareZone
      ? await deps.resolveOwnedCloudflareZone(detect.domain)
      : null;
    if (auth) return { kind: "cloudflare", auth, proof: { kind: "cf_account_owned" } };
    // NS is Cloudflare but the zone is NOT in our account — we cannot write it.
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

/** Read current records authoritatively via the write adapter; DoH fallback for manual. */
async function readCurrent(path: Path, domain: string, deps: ConnectDeps): Promise<DnsRecord[]> {
  const viaAdapter = async (id: string, auth: AdapterAuth | undefined): Promise<DnsRecord[] | null> => {
    const adapter = deps.getAdapter(id);
    if (!adapter?.readExisting) return null;
    try {
      return await adapter.readExisting(domain, auth);
    } catch {
      return null; // fall through to DoH
    }
  };

  if (path.kind === "cloudflare") {
    const r = await viaAdapter("cloudflare", path.auth);
    if (r) return r;
  } else if (path.kind === "adapter") {
    const r = await viaAdapter(path.adapterId, path.auth);
    if (r) return r;
  }

  if (deps.readExistingViaDns) {
    try {
      return await deps.readExistingViaDns(domain);
    } catch {
      return [];
    }
  }
  return [];
}

function buildRecords(input: ConnectInput, existing: DnsRecord[]): PlanResult {
  if (input.email) return planEmailRecords(input.email, existing);
  if (input.site) return planSiteRecords(input.site, existing);
  if (input.records) return { records: input.records, warnings: [] };
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
  const existing = await readCurrent(path, domain, deps);
  const plan = buildRecords(input, existing);
  const warnings = [...plan.warnings];
  const records = plan.records;

  // Never dead-end.
  if (path.kind === "manual") {
    return manualResult(domain, records, jobId, warnings, path.reason);
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
