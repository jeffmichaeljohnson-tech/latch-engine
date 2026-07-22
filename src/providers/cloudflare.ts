// Latch — Cloudflare adapter.
//
// A "dumb writer": it receives already-prepared canonical records (SPF merge,
// DKIM chunk, MX clobber-guard already happened upstream in connect()) and maps
// each one to a Cloudflare DNS API create. supportsApex is true because CF
// flattens CNAME-at-apex natively.
//
// Auth: an API token (Bearer). Read from AdapterAuth as { zoneId, token }.
// Secrets ride in AdapterAuth opaquely and are never logged.

import type {
  Adapter,
  AdapterApplyResult,
  AdapterAuth,
  AdapterCapabilities,
  AppliedRecord,
  DnsRecord,
  ManualRecord,
} from "../types";
import { LatchError } from "../types";

const CF_API = "https://api.cloudflare.com/client/v4";

interface CloudflareAuth {
  zoneId: string;
  token: string;
}

function readAuth(auth?: AdapterAuth): CloudflareAuth {
  const zoneId = auth?.["zoneId"];
  const token = auth?.["token"];
  if (typeof zoneId !== "string" || typeof token !== "string") {
    throw new LatchError(
      "provider_auth_failed",
      "Cloudflare adapter requires { zoneId, token } in auth.",
    );
  }
  return { zoneId, token };
}

/** Canonical host → full DNS name for the CF API. "@" is the zone apex. */
function toName(host: string, domain: string): string {
  if (host === "@" || host === "") return domain;
  if (host === domain || host.endsWith(`.${domain}`)) return host;
  return `${host}.${domain}`;
}

interface CfRecordBody {
  type: string;
  name: string;
  content: string;
  ttl: number;
  priority?: number;
}

function toCfBody(record: DnsRecord, domain: string): CfRecordBody {
  const body: CfRecordBody = {
    type: record.type,
    name: toName(record.host, domain),
    content: record.value,
    ttl: record.ttl,
  };
  if (record.type === "MX" && typeof record.priority === "number") {
    body.priority = record.priority;
  }
  return body;
}

export interface CfDnsRecord {
  id: string;
  type: string;
  name: string;
  content: string;
  ttl: number;
  priority?: number;
}

interface CfError {
  code: number;
  message: string;
}

interface CfResponse<T> {
  success: boolean;
  errors: CfError[];
  result: T | null;
}

function cfErrorText(errors: CfError[] | undefined): string {
  if (!errors || errors.length === 0) return "Cloudflare API rejected the record.";
  return errors.map((e) => `${e.code}: ${e.message}`).join("; ");
}

export const CLOUDFLARE_CAPABILITIES: AdapterCapabilities = {
  id: "cloudflare",
  displayName: "Cloudflare",
  automated: true,
  authKind: "api_key",
  writesRecordTypes: ["A", "AAAA", "CNAME", "CAA", "MX", "TXT", "NS"],
  supportsApex: true,
};

export class CloudflareAdapter implements Adapter {
  capabilities(): AdapterCapabilities {
    return CLOUDFLARE_CAPABILITIES;
  }

  async apply(
    domain: string,
    records: DnsRecord[],
    auth?: AdapterAuth,
  ): Promise<AdapterApplyResult> {
    const { zoneId, token } = readAuth(auth);
    const applied: AppliedRecord[] = [];
    const manual: ManualRecord[] = [];

    for (const record of records) {
      const res = await fetch(`${CF_API}/zones/${zoneId}/dns_records`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(toCfBody(record, domain)),
      });

      // Auth failure is a hard failure for the whole batch — stop and throw.
      if (res.status === 401 || res.status === 403) {
        throw new LatchError(
          "provider_auth_failed",
          "Cloudflare rejected the API token.",
        );
      }

      const json = (await res.json()) as CfResponse<CfDnsRecord>;
      if (!res.ok || !json.success || !json.result) {
        // Dumb writer: a single rejected record falls to the manual list.
        manual.push({ ...record, note: cfErrorText(json.errors) });
        continue;
      }
      applied.push({ ...record, recordId: json.result.id });
    }

    return { applied, manual };
  }
}

export const cloudflareAdapter = new CloudflareAdapter();

/**
 * Authoritative read-back for an owned zone — our real verify path (public DoH
 * only reflects the recursive cache). Lists records by type (+ name when the
 * host is not the apex) so the orchestrator can confirm a write landed.
 */
export async function readBack(
  zoneId: string,
  token: string,
  record: DnsRecord,
): Promise<CfDnsRecord[]> {
  const params = new URLSearchParams({ type: record.type });
  if (record.host && record.host !== "@") params.set("name", record.host);

  const res = await fetch(
    `${CF_API}/zones/${zoneId}/dns_records?${params.toString()}`,
    { headers: { Authorization: `Bearer ${token}` } },
  );
  if (res.status === 401 || res.status === 403) {
    throw new LatchError("provider_auth_failed", "Cloudflare rejected the API token.");
  }
  const json = (await res.json()) as CfResponse<CfDnsRecord[]>;
  if (!res.ok || !json.success || !json.result) {
    throw new LatchError("provider_rejected", cfErrorText(json.errors));
  }
  return json.result;
}
