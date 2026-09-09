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

/** Full DNS name → canonical host ("@" for the apex). Reverse of toName(). */
function toHost(name: string, domain: string): string {
  if (name === domain || name === `${domain}.`) return "@";
  if (name.endsWith(`.${domain}`)) return name.slice(0, -(domain.length + 1));
  return name;
}

/** Map a Cloudflare API record back to the canonical DnsRecord shape. */
function toDnsRecord(r: CfDnsRecord, domain: string): DnsRecord {
  const record: DnsRecord = {
    type: r.type as DnsRecord["type"],
    host: toHost(r.name, domain),
    value: r.content,
    ttl: r.ttl,
  };
  if (r.type === "MX" && typeof r.priority === "number") record.priority = r.priority;
  return record;
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

  /**
   * Authoritative read of the zone's current records (for connect()'s read-before-
   * write merges + MX clobber-guard). One page (per_page=100) — a zone with >100
   * records would need pagination (flagged; not needed for the email/site record
   * sets Latch writes).
   */
  async readExisting(domain: string, auth?: AdapterAuth): Promise<DnsRecord[]> {
    const { zoneId, token } = readAuth(auth);
    const res = await fetch(`${CF_API}/zones/${zoneId}/dns_records?per_page=100`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (res.status === 401 || res.status === 403) {
      throw new LatchError("provider_auth_failed", "Cloudflare rejected the API token.");
    }
    const json = (await res.json()) as CfResponse<CfDnsRecord[]>;
    if (!res.ok || !json.success || !json.result) {
      throw new LatchError("provider_rejected", cfErrorText(json.errors));
    }
    return json.result.map((r) => toDnsRecord(r, domain));
  }

  async apply(
    domain: string,
    records: DnsRecord[],
    auth?: AdapterAuth,
  ): Promise<AdapterApplyResult> {
    const { zoneId, token } = readAuth(auth);
    const applied: AppliedRecord[] = [];
    const manual: ManualRecord[] = [];

    // UPSERT, not create.
    //
    // This used to POST every record unconditionally. The engine's whole reason
    // for reading the zone first is to MERGE — `mergeSpf` folds our include into
    // whatever SPF is already there and returns one record — and then the writer
    // created that merged record BESIDE the original it had just merged from.
    // Two `v=spf1` TXTs at the apex is an RFC 7208 permerror: all mail fails.
    // The call returned `status: "applied"`.
    //
    // So the existing set is fetched once and keyed by (type, name). A match is
    // PUT; anything else is POST. Route 53 has always done this (it UPSERTs) and
    // Namecheap does it by union — Cloudflare, the only provider enabled by
    // default, was the one that did not.
    const existingById = new Map<string, string>();
    {
      const res = await fetch(`${CF_API}/zones/${zoneId}/dns_records?per_page=100`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.status === 401 || res.status === 403) {
        throw new LatchError("provider_auth_failed", "Cloudflare rejected the API token.");
      }
      const json = (await res.json()) as CfResponse<CfDnsRecord[]>;
      // A zone we cannot read is a zone we must not blind-write into: falling
      // back to POST here is exactly the duplicate-SPF bug, one level quieter.
      if (!res.ok || !json.success || !json.result) {
        throw new LatchError("provider_rejected", cfErrorText(json.errors));
      }
      for (const r of json.result) existingById.set(`${r.type}\u0000${r.name}`, r.id);
    }

    for (const record of records) {
      const body = toCfBody(record, domain);
      const key = `${body.type}\u0000${body.name}`;
      const existingId = existingById.get(key);
      const res = await fetch(
        existingId
          ? `${CF_API}/zones/${zoneId}/dns_records/${existingId}`
          : `${CF_API}/zones/${zoneId}/dns_records`,
        {
        method: existingId ? "PUT" : "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(body),
      },
      );

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
