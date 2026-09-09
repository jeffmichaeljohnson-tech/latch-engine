// Latch — Domain Connect (synchronous) adapter.
//
// Domain Connect's *sync* flow cannot write server-side: there is no client
// secret, so the DNS provider itself renders a consent page and applies the
// template. This adapter therefore does not write records — it builds the
// provider's sync-apply URL, which the UI opens in the system browser. The
// user consents at their DNS host and the host applies the template.
//
// providerId / serviceId / urlSyncUX come from detect() (the provider's
// _domainconnect settings endpoint). They are passed as config to the factory,
// because Adapter.authUrl(domain, redirectUri) has no place to receive them.
//
// Because apply() cannot write, it returns empty applied/manual. The
// orchestrator, seeing authKind "domain_connect_sync" and a non-null authUrl(),
// resolves connect() to status "oauth_required" and surfaces the URL.

import type {
  Adapter,
  AdapterApplyResult,
  AdapterCapabilities,
  DnsRecordType,
} from "../types";

const DEFAULT_WRITES: DnsRecordType[] = ["A", "AAAA", "CNAME", "MX", "TXT"];

export interface DomainConnectConfig {
  /** DNS provider id, e.g. "GoDaddy" (from the provider's settings endpoint). */
  providerId: string;
  /** Template service id, e.g. "gbuild-email". */
  serviceId: string;
  /** Provider sync UX base, e.g. "https://domainconnect.godaddy.com/sync". */
  urlSyncUX: string;
  /**
   * Template variables (UPPERCASE, per the Domain Connect SDK contract).
   * The orchestrator derives these from the prepared records before building
   * the URL — they become query params on the apply URL.
   */
  vars?: Record<string, string>;
  /** Opaque state echoed back on redirect for CSRF correlation. */
  state?: string;
  /** Optional group id restricting the template to a record group. */
  groupId?: string;
}

function buildSyncUrl(
  config: DomainConnectConfig,
  domain: string,
  redirectUri: string,
): string {
  const base = config.urlSyncUX.replace(/\/+$/, "");
  const path =
    `/v2/domainTemplates/providers/${encodeURIComponent(config.providerId)}` +
    `/services/${encodeURIComponent(config.serviceId)}/apply`;

  const params = new URLSearchParams();
  params.set("domain", domain);
  for (const [k, v] of Object.entries(config.vars ?? {})) params.set(k, v);
  if (config.groupId) params.set("groupId", config.groupId);
  params.set("redirect_uri", redirectUri);
  if (config.state) params.set("state", config.state);

  return `${base}${path}?${params.toString()}`;
}

export class DomainConnectAdapter implements Adapter {
  private readonly config: DomainConnectConfig | null;

  constructor(config?: DomainConnectConfig) {
    this.config = config ?? null;
  }

  capabilities(): AdapterCapabilities {
    return {
      id: "domain-connect",
      displayName: "Domain Connect",
      // Provider-mediated consent, not a silent write.
      automated: false,
      authKind: "domain_connect_sync",
      writesRecordTypes: DEFAULT_WRITES,
      // The provider applies the template; apex handling is the provider's.
      supportsApex: true,
    };
  }

  /** Builds the provider's sync-apply URL. null when unconfigured. */
  async authUrl(domain: string, redirectUri: string): Promise<string | null> {
    if (!this.config) return null;
    return buildSyncUrl(this.config, domain, redirectUri);
  }

  /**
   * Sync Domain Connect writes nothing server-side. Returns empty applied and
   * manual; the orchestrator uses authUrl() to drive an oauth_required flow.
   */
  async apply(): Promise<AdapterApplyResult> {
    return { applied: [], manual: [] };
  }
}

/** Registered default — unconfigured (authUrl → null until built per detect()). */
export const domainConnectAdapter = new DomainConnectAdapter();

/** Build a configured Domain Connect adapter from detect() output. */
export function makeDomainConnectAdapter(
  config: DomainConnectConfig,
): DomainConnectAdapter {
  return new DomainConnectAdapter(config);
}
