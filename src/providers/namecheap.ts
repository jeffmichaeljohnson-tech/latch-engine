// Latch — Namecheap adapter.
//
// HONEST CONSTRAINTS (do not overpromise this as universal novice one-click):
//   * Namecheap's public API is IP-ALLOWLISTED — every calling server IP must
//     be pre-registered in the account, so it does not work from an arbitrary
//     Worker edge without setup.
//   * It is ELIGIBILITY-GATED — the account needs 20+ domains, OR $50+ balance,
//     OR $50+ spent in the last two years, to get API access at all.
//   So this adapter targets qualifying accounts; for everyone else the polished
//   manual fallback (a different lane) is the guarantee.
//
// setHosts OVERWRITES ALL host records for the domain — there is no per-record
// create. So the required, adapter-local sequence is:
//   getHosts -> union incoming with existing (replace matching type+host, keep
//   the rest) -> setHosts. This host-union lives here on purpose; it is NOT the
//   email-DNS intelligence (SPF merge / DKIM chunk) that happens upstream.
//
// Auth rides in AdapterAuth as { apiUser, apiKey, userName, clientIp } and is
// never logged.

import type {
  Adapter,
  AdapterApplyResult,
  AdapterAuth,
  AdapterCapabilities,
  AppliedRecord,
  DnsRecord,
} from "../types";
import { LatchError } from "../types";

const NAMECHEAP_API = "https://api.namecheap.com/xml.response";

interface NamecheapAuth {
  apiUser: string;
  apiKey: string;
  userName: string;
  clientIp: string;
}

function readAuth(auth?: AdapterAuth): NamecheapAuth {
  const apiUser = auth?.["apiUser"];
  const apiKey = auth?.["apiKey"];
  const userName = auth?.["userName"] ?? apiUser;
  const clientIp = auth?.["clientIp"];
  if (
    typeof apiUser !== "string" ||
    typeof apiKey !== "string" ||
    typeof userName !== "string" ||
    typeof clientIp !== "string"
  ) {
    throw new LatchError(
      "provider_auth_failed",
      "Namecheap adapter requires { apiUser, apiKey, userName?, clientIp } in auth.",
    );
  }
  return { apiUser, apiKey, userName, clientIp };
}

/** SLD/TLD split on the first dot — handles multi-part TLDs (example.co.uk). */
function splitDomain(domain: string): { sld: string; tld: string } {
  const dot = domain.indexOf(".");
  if (dot < 0) throw new LatchError("provider_rejected", `Invalid domain: ${domain}`);
  return { sld: domain.slice(0, dot), tld: domain.slice(dot + 1) };
}

/** Canonical host → Namecheap host label. Namecheap uses "@" + bare labels. */
function toNamecheapHost(host: string, domain: string): string {
  if (host === "" || host === "@" || host === domain) return "@";
  if (host.endsWith(`.${domain}`)) return host.slice(0, -(domain.length + 1));
  return host;
}

/** A Namecheap host row — the shape setHosts writes and getHosts returns. */
interface HostRow {
  name: string;
  type: string;
  address: string;
  mxPref?: number;
  ttl: number;
}

function attr(fragment: string, name: string): string | undefined {
  const m = fragment.match(new RegExp(`${name}="([^"]*)"`, "i"));
  return m ? m[1] : undefined;
}

/** Minimal XML parse of a getHosts response into host rows. */
function parseHosts(xml: string): HostRow[] {
  const status = xml.match(/<ApiResponse[^>]*\bStatus="([^"]*)"/i)?.[1];
  if (status && status.toUpperCase() !== "OK") {
    const err = xml.match(/<Error[^>]*>([^<]*)<\/Error>/i)?.[1] ?? "Namecheap getHosts failed.";
    throw new LatchError("provider_rejected", err);
  }
  const rows: HostRow[] = [];
  for (const m of xml.matchAll(/<host\b([^>]*?)\/?>/gi)) {
    const frag = m[1] ?? "";
    const name = attr(frag, "Name");
    const type = attr(frag, "Type");
    const address = attr(frag, "Address");
    if (name === undefined || type === undefined || address === undefined) continue;
    const mxPref = attr(frag, "MXPref");
    const ttl = attr(frag, "TTL");
    rows.push({
      name,
      type,
      address,
      ...(mxPref !== undefined ? { mxPref: Number(mxPref) } : {}),
      ttl: ttl !== undefined ? Number(ttl) : 1800,
    });
  }
  return rows;
}

function toHostRow(record: DnsRecord, domain: string): HostRow {
  return {
    name: toNamecheapHost(record.host, domain),
    type: record.type,
    address: record.value,
    ...(record.type === "MX" && typeof record.priority === "number"
      ? { mxPref: record.priority }
      : {}),
    ttl: record.ttl,
  };
}

/**
 * TXT is the one multi-valued type where several UNRELATED records legitimately
 * share one owner name: an apex routinely carries SPF beside a Google, Microsoft
 * or Atlassian site-verification token. Keying the union on (type, host) alone
 * would make writing the SPF silently delete every one of them -- setHosts has no
 * per-record id, so whatever is left out of the body is gone.
 *
 * So a TXT row also carries a SLOT, taken from its own value:
 *   - a `v=<TAG>` prefix (spf1, DKIM1, DMARC1) is the slot, so a new SPF replaces
 *     the old SPF -- and only the SPF. Leaving it out would append a second
 *     v=spf1 at the apex, which is an RFC 7208 permerror and fails all mail.
 *   - anything else is its own slot, keyed by the exact value. An unrelated
 *     token is therefore never displaced, and rewriting the same value is
 *     idempotent. The trade is that changing an arbitrary TXT to a new arbitrary
 *     value ADDS rather than replaces; for a type whose records are additive by
 *     nature, erring toward keeping a stranger's record is the safe direction.
 *
 * Existing rows arrive from Namecheap XML with no purpose field, so the slot has
 * to be derived from the value -- it cannot be read off the record.
 */
function txtSlot(address: string): string {
  const tag = /^\s*"?\s*v\s*=\s*([A-Za-z0-9]+)/i.exec(address);
  return tag ? `v=${(tag[1] ?? "").toLowerCase()}` : address.trim();
}

function keyOf(name: string, type: string, address: string): string {
  const base = `${type.toUpperCase()}::${name.toLowerCase()}`;
  return type.toUpperCase() === "TXT" ? `${base}::${txtSlot(address)}` : base;
}

/**
 * Union: an incoming record REPLACES the existing row occupying the same slot --
 * (type, host) for every type, narrowed by the TXT slot above for TXT. Every
 * other existing row is preserved. Exported for direct unit testing.
 */
export function unionHosts(existing: HostRow[], incoming: HostRow[]): HostRow[] {
  const incomingKeys = new Set(incoming.map((r) => keyOf(r.name, r.type, r.address)));
  const kept = existing.filter((r) => !incomingKeys.has(keyOf(r.name, r.type, r.address)));
  return [...kept, ...incoming];
}

function buildSetHostsBody(
  auth: NamecheapAuth,
  domain: string,
  hosts: HostRow[],
): URLSearchParams {
  const { sld, tld } = splitDomain(domain);
  const body = new URLSearchParams();
  body.set("ApiUser", auth.apiUser);
  body.set("ApiKey", auth.apiKey);
  body.set("UserName", auth.userName);
  body.set("ClientIp", auth.clientIp);
  body.set("Command", "namecheap.domains.dns.setHosts");
  body.set("SLD", sld);
  body.set("TLD", tld);
  hosts.forEach((h, i) => {
    const n = i + 1;
    body.set(`HostName${n}`, h.name);
    body.set(`RecordType${n}`, h.type);
    body.set(`Address${n}`, h.address);
    body.set(`TTL${n}`, String(h.ttl));
    if (h.type.toUpperCase() === "MX") {
      body.set(`MXPref${n}`, String(h.mxPref ?? 10));
    }
  });
  return body;
}

export const NAMECHEAP_CAPABILITIES: AdapterCapabilities = {
  id: "namecheap",
  displayName: "Namecheap",
  automated: true,
  authKind: "api_key",
  writesRecordTypes: ["A", "AAAA", "CNAME", "CAA", "MX", "TXT", "NS"],
  // Namecheap supports ALIAS at apex, but this dumb writer does not synthesize
  // it; apex strategy is decided upstream, so we advertise conservatively.
  supportsApex: false,
};

export class NamecheapAdapter implements Adapter {
  capabilities(): AdapterCapabilities {
    return NAMECHEAP_CAPABILITIES;
  }

  async apply(
    domain: string,
    records: DnsRecord[],
    auth?: AdapterAuth,
  ): Promise<AdapterApplyResult> {
    const nc = readAuth(auth);
    const { sld, tld } = splitDomain(domain);

    // 1. Read the current host set.
    const getParams = new URLSearchParams({
      ApiUser: nc.apiUser,
      ApiKey: nc.apiKey,
      UserName: nc.userName,
      ClientIp: nc.clientIp,
      Command: "namecheap.domains.dns.getHosts",
      SLD: sld,
      TLD: tld,
    });
    const getRes = await fetch(`${NAMECHEAP_API}?${getParams.toString()}`);
    const getXml = await getRes.text();
    if (getRes.status === 401 || getRes.status === 403) {
      throw new LatchError("provider_auth_failed", "Namecheap rejected the API credentials.");
    }
    const existing = parseHosts(getXml);

    // 2. Union incoming over existing (replace matching type+host, keep rest).
    const incoming = records.map((r) => toHostRow(r, domain));
    const merged = unionHosts(existing, incoming);

    // 3. Overwrite the whole host set.
    const body = buildSetHostsBody(nc, domain, merged);
    const setRes = await fetch(NAMECHEAP_API, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    const setXml = await setRes.text();
    if (setRes.status === 401 || setRes.status === 403) {
      throw new LatchError("provider_auth_failed", "Namecheap rejected the API credentials.");
    }
    const status = setXml.match(/<ApiResponse[^>]*\bStatus="([^"]*)"/i)?.[1];
    if (!setRes.ok || (status && status.toUpperCase() !== "OK")) {
      const err = setXml.match(/<Error[^>]*>([^<]*)<\/Error>/i)?.[1] ?? "Namecheap setHosts failed.";
      throw new LatchError("provider_rejected", err);
    }

    // setHosts has no per-record ids; the records we asked to write are applied.
    const applied: AppliedRecord[] = records.map((r) => ({ ...r }));
    return { applied, manual: [] };
  }
}

export const namecheapAdapter = new NamecheapAdapter();
