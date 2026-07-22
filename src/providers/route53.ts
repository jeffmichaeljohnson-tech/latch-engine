// Latch — Amazon Route 53 adapter.
//
// A "dumb writer": receives already-prepared canonical records and UPSERTs them
// via ChangeResourceRecordSets. Route 53 is a global service signed against
// region us-east-1. Signing is SigV4 over Web Crypto (see ./sigv4) so it runs
// unchanged in a Worker and in Node.
//
// HONEST CONSTRAINT: needs user-supplied, scoped IAM credentials
// (route53:ChangeResourceRecordSets on the target hosted zone) — fine for
// technical users, not universal novice one-click. Creds ride in AdapterAuth as
// { accessKeyId, secretAccessKey, sessionToken?, hostedZoneId } and never log.

import type {
  Adapter,
  AdapterApplyResult,
  AdapterAuth,
  AdapterCapabilities,
  AppliedRecord,
  DnsRecord,
} from "../types";
import { LatchError } from "../types";
import { signRequest } from "./sigv4";

const ROUTE53_HOST = "route53.amazonaws.com";
const ROUTE53_ENDPOINT = `https://${ROUTE53_HOST}`;
const API_VERSION = "2013-04-01";
const REGION = "us-east-1";
const SERVICE = "route53";
const XMLNS = `https://${ROUTE53_HOST}/doc/${API_VERSION}/`;

interface Route53Auth {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
  hostedZoneId: string;
}

function readAuth(auth?: AdapterAuth): Route53Auth {
  const accessKeyId = auth?.["accessKeyId"];
  const secretAccessKey = auth?.["secretAccessKey"];
  const sessionToken = auth?.["sessionToken"];
  const hostedZoneId = auth?.["hostedZoneId"];
  if (
    typeof accessKeyId !== "string" ||
    typeof secretAccessKey !== "string" ||
    typeof hostedZoneId !== "string"
  ) {
    throw new LatchError(
      "provider_auth_failed",
      "Route 53 adapter requires { accessKeyId, secretAccessKey, hostedZoneId } in auth.",
    );
  }
  return {
    accessKeyId,
    secretAccessKey,
    hostedZoneId,
    ...(typeof sessionToken === "string" ? { sessionToken } : {}),
  };
}

/** Strip the "/hostedzone/" prefix AWS sometimes returns on zone ids. */
function normalizeZoneId(id: string): string {
  return id.replace(/^\/?hostedzone\//i, "");
}

function xmlEscape(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/** Canonical host → FQDN with a trailing dot (Route 53 record name form). */
function toFqdn(host: string, domain: string): string {
  let name: string;
  if (host === "" || host === "@" || host === domain) name = domain;
  else if (host.endsWith(`.${domain}`)) name = host;
  else name = `${host}.${domain}`;
  return name.endsWith(".") ? name : `${name}.`;
}

/**
 * The rdata Value for one record. MX prepends priority. TXT must be quoted for
 * Route 53 (a wire requirement, not email intelligence): a value already
 * starting with a quote is assumed pre-chunked upstream and passes through.
 */
function toValue(record: DnsRecord): string {
  if (record.type === "MX") {
    return `${record.priority ?? 10} ${record.value}`;
  }
  if (record.type === "TXT") {
    if (record.value.startsWith('"')) return record.value;
    const escaped = record.value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
    return `"${escaped}"`;
  }
  return record.value;
}

interface RecordSet {
  name: string;
  type: string;
  ttl: number;
  values: string[];
}

/** Group records by (name, type) — one ResourceRecordSet per group. */
function groupRecords(records: DnsRecord[], domain: string): RecordSet[] {
  const groups = new Map<string, RecordSet>();
  for (const record of records) {
    const name = toFqdn(record.host, domain);
    const type = record.type;
    const key = `${type}::${name}`;
    const set = groups.get(key);
    if (set) {
      set.values.push(toValue(record));
      set.ttl = Math.max(set.ttl, record.ttl);
    } else {
      groups.set(key, { name, type, ttl: record.ttl, values: [toValue(record)] });
    }
  }
  return [...groups.values()];
}

/** Build the ChangeResourceRecordSets request body (all changes are UPSERT). */
export function buildChangeBatchXml(domain: string, records: DnsRecord[]): string {
  const sets = groupRecords(records, domain);
  const changes = sets
    .map((set) => {
      const rrs = set.values
        .map((v) => `<ResourceRecord><Value>${xmlEscape(v)}</Value></ResourceRecord>`)
        .join("");
      return (
        `<Change><Action>UPSERT</Action>` +
        `<ResourceRecordSet>` +
        `<Name>${xmlEscape(set.name)}</Name>` +
        `<Type>${set.type}</Type>` +
        `<TTL>${set.ttl}</TTL>` +
        `<ResourceRecords>${rrs}</ResourceRecords>` +
        `</ResourceRecordSet></Change>`
      );
    })
    .join("");
  return (
    `<?xml version="1.0" encoding="UTF-8"?>` +
    `<ChangeResourceRecordSetsRequest xmlns="${XMLNS}">` +
    `<ChangeBatch><Changes>${changes}</Changes></ChangeBatch>` +
    `</ChangeResourceRecordSetsRequest>`
  );
}

export const ROUTE53_CAPABILITIES: AdapterCapabilities = {
  id: "route53",
  displayName: "Amazon Route 53",
  automated: true,
  authKind: "iam",
  writesRecordTypes: ["A", "AAAA", "CNAME", "CAA", "MX", "TXT", "NS"],
  // Route 53 alias records cover the apex; the orchestrator decides the strategy.
  supportsApex: true,
};

export class Route53Adapter implements Adapter {
  capabilities(): AdapterCapabilities {
    return ROUTE53_CAPABILITIES;
  }

  async apply(
    domain: string,
    records: DnsRecord[],
    auth?: AdapterAuth,
  ): Promise<AdapterApplyResult> {
    const creds = readAuth(auth);
    if (records.length === 0) return { applied: [], manual: [] };

    const zoneId = normalizeZoneId(creds.hostedZoneId);
    const path = `/${API_VERSION}/hostedzone/${zoneId}/rrset`;
    const url = `${ROUTE53_ENDPOINT}${path}`;
    const body = buildChangeBatchXml(domain, records);

    const signed = await signRequest({
      method: "POST",
      url,
      region: REGION,
      service: SERVICE,
      accessKeyId: creds.accessKeyId,
      secretAccessKey: creds.secretAccessKey,
      ...(creds.sessionToken ? { sessionToken: creds.sessionToken } : {}),
      body,
    });

    const res = await fetch(url, {
      method: "POST",
      headers: { ...signed.headers, "Content-Type": "application/xml" },
      body,
    });
    const text = await res.text();

    if (res.status === 401 || res.status === 403) {
      throw new LatchError("provider_auth_failed", route53Error(text));
    }
    if (!res.ok) {
      throw new LatchError("provider_rejected", route53Error(text));
    }

    // ChangeResourceRecordSets is atomic — the whole batch applied.
    const applied: AppliedRecord[] = records.map((r) => ({ ...r }));
    return { applied, manual: [] };
  }
}

function route53Error(xml: string): string {
  const code = xml.match(/<Code>([^<]*)<\/Code>/i)?.[1];
  const message = xml.match(/<Message>([^<]*)<\/Message>/i)?.[1];
  if (code || message) return `${code ?? "Error"}: ${message ?? "Route 53 rejected the change."}`;
  return "Route 53 rejected the change.";
}

export const route53Adapter = new Route53Adapter();
