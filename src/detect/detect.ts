// Latch — detection orchestrator.
//
// `detect(domain, resolver, opts?)` resolves a domain to its DNS host and picks
// the write method, assembling the canonical DetectResult (../types). All DNS
// goes through the injected Resolver; Domain Connect settings fetch is injected
// via opts.fetchSettings (tests pass fakes — no network in unit tests).
//
// Pipeline:
//   1. Resolve NS (authoritative-ish; DoH is recursive — see resolver.ts note).
//      NXDOMAIN → registered:false. Registered but no NS → not delegated.
//   2. Map NS suffix → provider identity (ns-map).
//   3. Read existing MX (existingMx), flag DNSSEC (DS / DNSKEY / AD), flag parked.
//   4. Prefer Domain Connect when live discovery confirms it.
//   5. Otherwise choose the method from the provider's treatment; unknown → manual.

import type { DetectResult, DetectMethod } from "../types";
import type { Resolver, DnsAnswer, DnsResponse } from "../net/resolver";
import { matchNameservers, normalizeNs, type ProviderIdentity } from "./ns-map";
import {
  discoverDomainConnect,
  type SettingsFetcher,
  type DomainConnectResult,
} from "./domain-connect";

const RCODE_NXDOMAIN = 3;
const RR_NS = 2;
const RR_MX = 15;
const RR_DS = 43;
const RR_DNSKEY = 48;

export interface DetectOptions {
  /**
   * Enables Domain Connect discovery. When present, detect() probes the
   * `_domainconnect` TXT and fetches the settings doc through it. Omit to skip
   * discovery (method then rests on NS-based treatment).
   */
  fetchSettings?: SettingsFetcher;
  /** Set false to skip Domain Connect discovery even if fetchSettings is given. */
  attemptDomainConnect?: boolean;
}

/** Lowercase, strip a trailing dot and any leading protocol/path noise. */
function normalizeDomain(domain: string): string {
  return domain.trim().toLowerCase().replace(/\.$/, "");
}

function answersOfType(resp: DnsResponse, rrType: number): DnsAnswer[] {
  return (resp.Answer ?? []).filter((a) => a.type === rrType);
}

/** Parse an MX record's DoH data ("10 mail.example.com.") into its target host. */
function mxTarget(data: string): string {
  const parts = data.trim().split(/\s+/);
  const target = parts.length > 1 ? parts[parts.length - 1]! : parts[0]!;
  return normalizeNs(target);
}

async function safeQuery(
  resolver: Resolver,
  name: string,
  type: Parameters<Resolver["query"]>[1],
  opts?: Parameters<Resolver["query"]>[2],
): Promise<DnsResponse | null> {
  try {
    return await resolver.query(name, type, opts);
  } catch {
    return null;
  }
}

function baseResult(domain: string): DetectResult {
  return {
    domain,
    dnsHost: null,
    method: "manual",
    confidence: 0,
    dnssec: false,
    registered: false,
    parked: false,
    existingMx: [],
    nameservers: [],
  };
}

export async function detect(
  domain: string,
  resolver: Resolver,
  opts: DetectOptions = {},
): Promise<DetectResult> {
  const zone = normalizeDomain(domain);
  const result = baseResult(zone);

  // ---- 1. Nameservers + registration/delegation ----
  const nsResp = await safeQuery(resolver, zone, "NS");

  if (nsResp && nsResp.Status === RCODE_NXDOMAIN) {
    // Domain does not exist → not registered.
    return { ...result, registered: false, confidence: 0.9 };
  }

  const nameservers = nsResp
    ? answersOfType(nsResp, RR_NS).map((a) => normalizeNs(a.data))
    : [];
  result.nameservers = nameservers;
  result.registered = nsResp ? nsResp.Status !== RCODE_NXDOMAIN : false;

  if (nameservers.length === 0) {
    // Registered (or unknown) but no delegation observed → nothing to automate.
    return { ...result, method: "manual", dnsHost: null, confidence: 0.4 };
  }

  // ---- 2. Provider identity ----
  const provider = matchNameservers(nameservers);
  result.dnsHost = provider ? provider.displayName : null;

  // ---- 3. Existing MX + DNSSEC ----
  const mxResp = await safeQuery(resolver, zone, "MX");
  if (mxResp) {
    result.existingMx = answersOfType(mxResp, RR_MX)
      .map((a) => mxTarget(a.data))
      .filter((t) => t.length > 0 && t !== ".");
  }
  result.dnssec = await detectDnssec(resolver, zone, nsResp);

  // ---- 3b. Parked ----
  if (provider?.parking) {
    return { ...result, parked: true, method: "manual", confidence: 0.7 };
  }

  // ---- 4. Domain Connect discovery (authoritative when it confirms) ----
  const dc = await maybeDiscoverDomainConnect(zone, resolver, provider, opts);
  if (dc?.supported) {
    const authUrl = dc.urlSyncUX ?? dc.urlAsyncUX;
    return {
      ...result,
      method: "domain_connect",
      dnsHost: result.dnsHost ?? dc.providerName ?? null,
      ...(authUrl ? { authUrl } : {}),
      confidence: 0.97,
    };
  }

  // ---- 5. Treatment-based method ----
  const { method, confidence } = chooseMethod(provider);
  return { ...result, method, confidence };
}

/** DNSSEC signed if a DS or DNSKEY RR exists, or a query authenticates (AD). */
async function detectDnssec(
  resolver: Resolver,
  zone: string,
  nsResp: DnsResponse | null,
): Promise<boolean> {
  if (nsResp?.AD) return true;
  const ds = await safeQuery(resolver, zone, "DS", { dnssec: true });
  if (ds) {
    if (ds.AD) return true;
    if (answersOfType(ds, RR_DS).length > 0) return true;
  }
  const dnskey = await safeQuery(resolver, zone, "DNSKEY", { dnssec: true });
  if (dnskey && answersOfType(dnskey, RR_DNSKEY).length > 0) return true;
  return false;
}

async function maybeDiscoverDomainConnect(
  zone: string,
  resolver: Resolver,
  provider: ProviderIdentity | null,
  opts: DetectOptions,
): Promise<DomainConnectResult | null> {
  if (opts.attemptDomainConnect === false) return null;
  if (!opts.fetchSettings) return null;
  // Probe every domain — discovery can find Domain Connect on hosts the NS map
  // doesn't recognize. provider.domainConnectLikely only signals higher priors.
  return discoverDomainConnect(zone, resolver, opts.fetchSettings);
}

function chooseMethod(provider: ProviderIdentity | null): {
  method: DetectMethod;
  confidence: number;
} {
  if (!provider) {
    // Delegated to a host we don't recognize → honest manual fallback.
    return { method: "manual", confidence: 0.3 };
  }
  switch (provider.treatment) {
    case "cloudflare":
      return { method: "cloudflare", confidence: 0.9 };
    case "adapter":
      return {
        method: `adapter:${provider.adapterId ?? provider.id}`,
        confidence: 0.85,
      };
    case "domain_connect":
      // Recognized as DC-capable but live discovery didn't confirm (no
      // fetchSettings, or the probe failed). Can't run the flow without the
      // settings doc → manual, but we still name the host.
      return { method: "manual", confidence: 0.75 };
    case "manual":
    default:
      // Recognized host, no automated writer.
      return { method: "manual", confidence: 0.8 };
  }
}
