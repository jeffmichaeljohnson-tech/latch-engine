// Latch — Domain Connect discovery.
//
// Domain Connect (https://www.domainconnect.org/) lets a DNS provider advertise
// a hosted flow that applies records without the user hand-editing a zone or us
// holding a provider secret. Discovery is a two-step probe:
//
//   1. TXT `_domainconnect.<zone>`  → the provider's Domain Connect API host
//      (usually a bare hostname, e.g. "domainconnect.godaddy.com"; occasionally
//      a full URL).
//   2. GET `https://<host>/v2/<domain>/settings` → JSON advertising the flow
//      endpoints: urlSyncUX (hosted synchronous consent UX), urlAsyncUX
//      (OAuth async flow), urlAPI (direct template apply), plus providerId /
//      providerName.
//
// The DNS lookup uses the injected Resolver (no sockets here). The settings
// fetch is injected too (SettingsFetcher) so unit tests never hit the network.

import type { Resolver } from "../net/resolver";
import { readTxt } from "../net/resolver";

/** The subset of a Domain Connect /v2/<domain>/settings response we consume. */
export interface DomainConnectSettings {
  providerId?: string;
  providerName?: string;
  /** Base URL of the hosted synchronous consent UX. */
  urlSyncUX?: string;
  /** Base URL of the OAuth-based asynchronous flow. */
  urlAsyncUX?: string;
  /** Base URL of the direct template-apply API. */
  urlAPI?: string;
  width?: number;
  height?: number;
}

/**
 * Fetches a Domain Connect settings document. Injected so it can be mocked.
 * Returns null on any non-OK / unreachable / unparseable response — discovery
 * then reports unsupported rather than throwing.
 */
export type SettingsFetcher = (url: string) => Promise<DomainConnectSettings | null>;

export interface DomainConnectResult {
  supported: boolean;
  providerId?: string;
  providerName?: string;
  urlSyncUX?: string;
  urlAsyncUX?: string;
  urlAPI?: string;
}

const UNSUPPORTED: DomainConnectResult = { supported: false };

/** Build the settings URL from the `_domainconnect` TXT value (host or full URL). */
export function settingsUrl(txtValue: string, domain: string): string {
  const trimmed = txtValue.trim();
  const base = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  const root = base.replace(/\/+$/, "");
  return `${root}/v2/${domain}/settings`;
}

/**
 * Discover whether `zone` supports Domain Connect. Never throws — any failure
 * (no TXT, unreachable settings, malformed JSON) resolves to { supported:false }.
 */
export async function discoverDomainConnect(
  zone: string,
  resolver: Resolver,
  fetchSettings: SettingsFetcher,
): Promise<DomainConnectResult> {
  let txtValues: string[];
  try {
    const resp = await resolver.query(`_domainconnect.${zone}`, "TXT");
    txtValues = readTxt(resp);
  } catch {
    return UNSUPPORTED;
  }

  const host = txtValues.map((v) => v.trim()).find((v) => v.length > 0);
  if (!host) return UNSUPPORTED;

  let settings: DomainConnectSettings | null;
  try {
    settings = await fetchSettings(settingsUrl(host, zone));
  } catch {
    return UNSUPPORTED;
  }
  if (!settings) return UNSUPPORTED;

  // A usable Domain Connect provider advertises at least one flow endpoint.
  if (!settings.urlSyncUX && !settings.urlAsyncUX && !settings.urlAPI) {
    return UNSUPPORTED;
  }

  return {
    supported: true,
    providerId: settings.providerId,
    providerName: settings.providerName,
    urlSyncUX: settings.urlSyncUX,
    urlAsyncUX: settings.urlAsyncUX,
    urlAPI: settings.urlAPI,
  };
}
