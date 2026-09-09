// Latch — declarative manifest adapter (the SAFE form of "agent-derived adapters").
//
// An agent (or a human) can describe a provider's DNS-write API as pure DATA — a
// manifest — that the engine INTERPRETS at runtime. There is NEVER generated code,
// NEVER eval/Function, NEVER a code path that issues a DELETE. The interpreter only
// substitutes declarative placeholders as plain text and POSTs (or PUT/PATCH upserts)
// via global fetch.
//
// Safety posture (runtime codegen of a DNS-writing adapter with real
// creds is the highest blast-radius surface, so it is disallowed):
//  - manifest is DATA, interpreted; no expressions, no code.
//  - upsert/create only — the interpreter has no branch that emits a DELETE, and
//    validateManifest rejects a DELETE method anywhere.
//  - TRUST IS PROVENANCE-BASED, NOT SELF-ASSERTED. Trust is a CALLER-supplied option
//    (`ManifestAdapterOptions.trusted`), never a field on the manifest JSON — so an
//    agent-proposed manifest has no way to bless itself. Without `trusted:true` from
//    the reviewing caller, apply() throws; the manifest can still be DRY-RUN
//    (dryRun() renders the would-be requests without sending) for a human to review
//    exactly what it would do. Only after that review does GBuild pass trusted:true.
//    The agent-derived-adapter generation path MUST NOT be the thing that sets trust.

import type {
  Adapter,
  AdapterApplyResult,
  AdapterAuth,
  AdapterAuthKind,
  AdapterCapabilities,
  AppliedRecord,
  DnsRecord,
  DnsRecordType,
  ManualRecord,
} from "../types";
import { LatchError } from "../types";
import { registerAdapter } from "./registry";

// ---------------------------------------------------------------------------
// Manifest shape (JSON-serializable — an agent proposes it as data)
// ---------------------------------------------------------------------------

/** Placeholders a bodyTemplate / path / header value may reference. Record-derived only. */
export const KNOWN_PLACEHOLDERS = [
  "type",
  "host",
  "value",
  "ttl",
  "priority",
  "fqdn",
] as const;
export type KnownPlaceholder = (typeof KNOWN_PLACEHOLDERS)[number];

/** Write methods the interpreter permits. DELETE is deliberately absent — upsert only. */
const ALLOWED_CREATE_METHODS = new Set(["POST", "PUT", "PATCH"]);
/** Read methods the interpreter permits (a list/read is never a write). */
const ALLOWED_READ_METHODS = new Set(["GET", "POST"]);

const AUTH_KINDS: ReadonlySet<AdapterAuthKind> = new Set<AdapterAuthKind>([
  "none",
  "oauth",
  "api_key",
  "iam",
  "domain_connect_sync",
]);

const DNS_RECORD_TYPES: ReadonlySet<DnsRecordType> = new Set<DnsRecordType>([
  "A",
  "AAAA",
  "CNAME",
  "CAA",
  "MX",
  "TXT",
  "NS",
]);

/**
 * A JSON body template. String leaves may contain declarative placeholders
 * (`{type}`, `{fqdn}`, …). A leaf that is EXACTLY `{ttl}` or `{priority}` is
 * substituted with the typed number (and a `{priority}` on a non-MX record drops
 * the key). No expressions — substitution is plain text replace.
 */
export type BodyTemplate =
  | string
  | number
  | boolean
  | null
  | BodyTemplate[]
  | { [k: string]: BodyTemplate };

/** How a provider's list/read response maps back to the canonical DnsRecord shape. */
export interface ManifestRecordMap {
  type: string;
  host: string;
  value: string;
  ttl: string;
  priority?: string;
}

export interface ManifestCreate {
  /** Path appended to baseUrl. May reference `{auth:<key>}` and record placeholders. */
  path: string;
  /** POST | PUT | PATCH — never DELETE. Defaults to POST. */
  method?: string;
  /** Header values may reference `{auth:<key>}` (e.g. `Bearer {auth:token}`). */
  headers?: Record<string, string>;
  bodyTemplate: BodyTemplate;
}

export interface ManifestRead {
  path: string;
  /** GET | POST — never DELETE. Defaults to GET. */
  method?: string;
  headers?: Record<string, string>;
  /** Dot-path to the records array in the response (e.g. "result"). */
  recordsPath: string;
  /** Field mapping; defaults to canonical keys ({type,host,value,ttl,priority}). */
  recordMap?: ManifestRecordMap;
}

export interface ManifestCapabilities {
  writesRecordTypes: DnsRecordType[];
  supportsApex: boolean;
  /** Declared automation; effective `automated` is still gated on `trusted`. */
  automated?: boolean;
}

export interface AdapterManifest {
  id: string;
  displayName: string;
  authKind: AdapterAuthKind;
  /** http(s) only — validated. */
  baseUrl: string;
  capabilities: ManifestCapabilities;
  create: ManifestCreate;
  read?: ManifestRead;
  /** Dot-path to the created record's id in the create response (e.g. "result.id"). */
  responseIdPath: string;
  // NOTE: trust is NOT a manifest field — it is a caller-supplied option
  // (ManifestAdapterOptions.trusted), so an agent-proposed manifest cannot self-bless.
}

/** A rendered, would-be HTTP request — what a dry-run returns instead of sending. */
export interface ManifestRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string;
  record: DnsRecord;
}

export interface ManifestAdapterOptions {
  /** Override fetch (tests). Defaults to the global `fetch` at call time. */
  fetch?: typeof fetch;
  /**
   * Caller-supplied trust from the reviewing system (GBuild). ONLY `true` lets
   * apply() write DNS. Never read from the manifest JSON — an agent-proposed
   * manifest cannot self-assert trust. Defaults to untrusted (dry-run only).
   */
  trusted?: boolean;
}

export interface ManifestAdapter extends Adapter {
  /**
   * Render the would-be HTTP requests WITHOUT sending. Safe for an untrusted
   * manifest — a human reviews exactly what it would do before granting trust.
   */
  dryRun(domain: string, records: DnsRecord[], auth?: AdapterAuth): ManifestRequest[];
  readonly manifest: AdapterManifest;
}

export type ValidateResult =
  | { ok: true }
  | { ok: false; errors: string[] };

// ---------------------------------------------------------------------------
// Placeholder helpers (plain text substitution — never eval)
// ---------------------------------------------------------------------------

const PLACEHOLDER_RE = /\{([^}]+)\}/g;

function tokensIn(text: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(PLACEHOLDER_RE)) out.push(m[1]!);
  return out;
}

/** Collect every string leaf of a body template (for placeholder validation). */
function stringLeaves(t: BodyTemplate): string[] {
  if (typeof t === "string") return [t];
  if (Array.isArray(t)) return t.flatMap(stringLeaves);
  if (t !== null && typeof t === "object") return Object.values(t).flatMap(stringLeaves);
  return [];
}

/** Canonical host → full DNS name. "@"/"" is the zone apex. */
function toFqdn(host: string, domain: string): string {
  if (host === "@" || host === "") return domain;
  if (host === domain || host.endsWith(`.${domain}`)) return host;
  return `${host}.${domain}`;
}

/** Full DNS name → canonical host ("@" for the apex). Reverse of toFqdn(). */
function toHost(name: string, domain: string): string {
  if (name === domain || name === `${domain}.`) return "@";
  if (name.endsWith(`.${domain}`)) return name.slice(0, -(domain.length + 1));
  return name;
}

function recordValues(record: DnsRecord, domain: string): Record<string, string> {
  return {
    type: record.type,
    host: record.host,
    value: record.value,
    ttl: String(record.ttl),
    priority: record.priority == null ? "" : String(record.priority),
    fqdn: toFqdn(record.host, domain),
  };
}

/**
 * Substitute placeholders in a string as TEXT. `{auth:<key>}` pulls from the opaque
 * auth bag; record placeholders pull from `values`. Unknown record placeholders were
 * rejected at validation time; a missing auth value is a hard auth failure.
 */
function substitute(
  text: string,
  values: Record<string, string>,
  auth: AdapterAuth | undefined,
): string {
  return text.replace(PLACEHOLDER_RE, (_full, token: string) => {
    if (token.startsWith("auth:")) {
      const key = token.slice("auth:".length);
      const v = auth?.[key];
      if (v == null) {
        throw new LatchError(
          "provider_auth_failed",
          `manifest adapter requires auth field "${key}".`,
        );
      }
      return String(v);
    }
    return values[token] ?? "";
  });
}

/** Render a body template to a concrete JSON value (typed ttl/priority, dropped empties). */
function renderBody(
  t: BodyTemplate,
  values: Record<string, string>,
  auth: AdapterAuth | undefined,
  record: DnsRecord,
): unknown {
  if (typeof t === "string") {
    if (t === "{ttl}") return record.ttl;
    if (t === "{priority}") return record.priority; // undefined ⇒ key dropped below
    return substitute(t, values, auth);
  }
  if (Array.isArray(t)) {
    return t.map((el) => renderBody(el, values, auth, record)).filter((v) => v !== undefined);
  }
  if (t !== null && typeof t === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(t)) {
      const rendered = renderBody(v, values, auth, record);
      if (rendered !== undefined) out[k] = rendered;
    }
    return out;
  }
  return t;
}

function joinUrl(baseUrl: string, path: string): string {
  return `${baseUrl.replace(/\/$/, "")}/${path.replace(/^\//, "")}`;
}

function getByPath(obj: unknown, path: string): unknown {
  return path.split(".").reduce<unknown>((acc, key) => {
    if (acc == null || typeof acc !== "object") return undefined;
    return (acc as Record<string, unknown>)[key];
  }, obj);
}

// ---------------------------------------------------------------------------
// validateManifest — structural + safety validation
// ---------------------------------------------------------------------------

const DEFAULT_RECORD_MAP: ManifestRecordMap = {
  type: "type",
  host: "host",
  value: "value",
  ttl: "ttl",
  priority: "priority",
};

function validatePlaceholders(
  text: string,
  where: string,
  allowAuth: boolean,
  errors: string[],
): void {
  for (const token of tokensIn(text)) {
    if (token.startsWith("auth:")) {
      if (!allowAuth) {
        errors.push(`${where}: auth placeholder "{${token}}" is not allowed here.`);
      } else if (token.length <= "auth:".length) {
        errors.push(`${where}: empty auth placeholder "{${token}}".`);
      }
      continue;
    }
    if (!(KNOWN_PLACEHOLDERS as readonly string[]).includes(token)) {
      errors.push(`${where}: unknown placeholder "{${token}}".`);
    }
  }
}

export function validateManifest(m: unknown): ValidateResult {
  const errors: string[] = [];
  if (m === null || typeof m !== "object") {
    return { ok: false, errors: ["manifest must be an object."] };
  }
  const man = m as Partial<AdapterManifest>;

  if (typeof man.id !== "string" || man.id.trim() === "") errors.push("id: required non-empty string.");
  if (typeof man.displayName !== "string" || man.displayName.trim() === "") {
    errors.push("displayName: required non-empty string.");
  }
  if (typeof man.authKind !== "string" || !AUTH_KINDS.has(man.authKind as AdapterAuthKind)) {
    errors.push("authKind: must be a known AdapterAuthKind.");
  }
  if (typeof man.responseIdPath !== "string" || man.responseIdPath.trim() === "") {
    errors.push("responseIdPath: required non-empty string.");
  }

  // baseUrl — http(s) only.
  if (typeof man.baseUrl !== "string") {
    errors.push("baseUrl: required string.");
  } else {
    let proto = "";
    try {
      proto = new URL(man.baseUrl).protocol;
    } catch {
      proto = "";
    }
    if (proto !== "http:" && proto !== "https:") {
      errors.push("baseUrl: must be an http(s) URL.");
    }
  }

  // capabilities
  const caps = man.capabilities;
  if (caps === null || typeof caps !== "object") {
    errors.push("capabilities: required object.");
  } else {
    const types = (caps as ManifestCapabilities).writesRecordTypes;
    if (!Array.isArray(types) || types.length === 0) {
      errors.push("capabilities.writesRecordTypes: non-empty array required.");
    } else {
      for (const t of types) {
        if (!DNS_RECORD_TYPES.has(t)) errors.push(`capabilities.writesRecordTypes: unknown type "${t}".`);
      }
    }
    if (typeof (caps as ManifestCapabilities).supportsApex !== "boolean") {
      errors.push("capabilities.supportsApex: boolean required.");
    }
  }

  // create — the write path. Method allowlist EXCLUDES DELETE by construction.
  const create = man.create;
  if (create === null || typeof create !== "object") {
    errors.push("create: required object.");
  } else {
    const c = create as ManifestCreate;
    if (typeof c.path !== "string" || c.path.trim() === "") errors.push("create.path: required string.");
    else validatePlaceholders(c.path, "create.path", true, errors);

    const method = (c.method ?? "POST").toUpperCase();
    if (method === "DELETE") {
      errors.push("create.method: DELETE is not permitted (upsert-only interpreter).");
    } else if (!ALLOWED_CREATE_METHODS.has(method)) {
      errors.push(`create.method: "${method}" not allowed (use POST/PUT/PATCH).`);
    }
    if (c.headers != null) {
      if (typeof c.headers !== "object") errors.push("create.headers: must be an object.");
      else {
        for (const [k, v] of Object.entries(c.headers)) {
          if (typeof v !== "string") errors.push(`create.headers.${k}: must be a string.`);
          else validatePlaceholders(v, `create.headers.${k}`, true, errors);
        }
      }
    }
    if (c.bodyTemplate === undefined) errors.push("create.bodyTemplate: required.");
    else {
      // bodyTemplate is record data only — auth placeholders are NOT allowed in the body.
      for (const leaf of stringLeaves(c.bodyTemplate)) {
        validatePlaceholders(leaf, "create.bodyTemplate", false, errors);
      }
    }
  }

  // read — optional list/read path. Also never DELETE.
  const read = man.read;
  if (read != null) {
    if (typeof read !== "object") {
      errors.push("read: must be an object.");
    } else {
      const r = read as ManifestRead;
      if (typeof r.path !== "string" || r.path.trim() === "") errors.push("read.path: required string.");
      else validatePlaceholders(r.path, "read.path", true, errors);

      const method = (r.method ?? "GET").toUpperCase();
      if (method === "DELETE") {
        errors.push("read.method: DELETE is not permitted.");
      } else if (!ALLOWED_READ_METHODS.has(method)) {
        errors.push(`read.method: "${method}" not allowed (use GET/POST).`);
      }
      if (typeof r.recordsPath !== "string" || r.recordsPath.trim() === "") {
        errors.push("read.recordsPath: required string.");
      }
      if (r.headers != null) {
        if (typeof r.headers !== "object") errors.push("read.headers: must be an object.");
        else {
          for (const [k, v] of Object.entries(r.headers)) {
            if (typeof v !== "string") errors.push(`read.headers.${k}: must be a string.`);
            else validatePlaceholders(v, `read.headers.${k}`, true, errors);
          }
        }
      }
    }
  }

  return errors.length === 0 ? { ok: true } : { ok: false, errors };
}

// ---------------------------------------------------------------------------
// manifestAdapter — interprets a manifest as an Adapter
// ---------------------------------------------------------------------------

function renderHeaders(
  headers: Record<string, string> | undefined,
  values: Record<string, string>,
  auth: AdapterAuth | undefined,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers ?? {})) {
    out[k] = substitute(v, values, auth);
  }
  return out;
}

function renderRequest(
  m: AdapterManifest,
  record: DnsRecord,
  domain: string,
  auth: AdapterAuth | undefined,
): ManifestRequest {
  const values = recordValues(record, domain);
  const method = (m.create.method ?? "POST").toUpperCase();
  // Defense in depth: the interpreter must never emit a DELETE even if a manifest
  // slipped past validation. There is no code path here that constructs one.
  if (method === "DELETE") {
    throw new LatchError("unsupported", "manifest interpreter refuses a DELETE method.");
  }
  const headers = renderHeaders(m.create.headers, values, auth);
  if (headers["Content-Type"] == null && headers["content-type"] == null) {
    headers["Content-Type"] = "application/json";
  }
  return {
    url: joinUrl(m.baseUrl, substitute(m.create.path, values, auth)),
    method,
    headers,
    body: JSON.stringify(renderBody(m.create.bodyTemplate, values, auth, record)),
    record,
  };
}

export function manifestAdapter(
  m: AdapterManifest,
  opts?: ManifestAdapterOptions,
): ManifestAdapter {
  const capabilities = (): AdapterCapabilities => ({
    id: m.id,
    displayName: m.displayName,
    // Honest: without caller-granted trust it cannot write, so it never advertises automation.
    automated: opts?.trusted === true && (m.capabilities.automated ?? true),
    authKind: m.authKind,
    writesRecordTypes: m.capabilities.writesRecordTypes,
    supportsApex: m.capabilities.supportsApex,
  });

  const dryRun = (
    domain: string,
    records: DnsRecord[],
    auth?: AdapterAuth,
  ): ManifestRequest[] => records.map((r) => renderRequest(m, r, domain, auth));

  const apply = async (
    domain: string,
    records: DnsRecord[],
    auth?: AdapterAuth,
  ): Promise<AdapterApplyResult> => {
    // SAFETY GATE: apply() writes DNS only when the REVIEWING CALLER passes trusted:true.
    // Trust is never read from the manifest, so an agent-proposed manifest can't bless itself.
    if (opts?.trusted !== true) {
      throw new LatchError(
        "unsupported",
        `manifest adapter "${m.id}" is not trusted; apply() is disabled. ` +
          "Use dryRun() to review its requests, then have a human pass { trusted: true }.",
      );
    }
    const doFetch = opts?.fetch ?? fetch;
    const applied: AppliedRecord[] = [];
    const manual: ManualRecord[] = [];

    for (const record of records) {
      const req = renderRequest(m, record, domain, auth);
      const res = await doFetch(req.url, {
        method: req.method,
        headers: req.headers,
        body: req.body,
      });

      if (res.status === 401 || res.status === 403) {
        throw new LatchError("provider_auth_failed", `${m.displayName} rejected the credentials.`);
      }

      let json: unknown = undefined;
      try {
        json = await res.json();
      } catch {
        json = undefined;
      }

      if (!res.ok) {
        manual.push({ ...record, note: `${m.displayName} rejected the record (HTTP ${res.status}).` });
        continue;
      }

      const id = getByPath(json, m.responseIdPath);
      applied.push({
        ...record,
        ...(typeof id === "string" || typeof id === "number" ? { recordId: String(id) } : {}),
      });
    }

    return { applied, manual };
  };

  const readExisting = m.read
    ? async (domain: string, auth?: AdapterAuth): Promise<DnsRecord[]> => {
        const read = m.read!;
        const doFetch = opts?.fetch ?? fetch;
        const method = (read.method ?? "GET").toUpperCase();
        // No per-record context on a read — only auth placeholders resolve.
        const headers = renderHeaders(read.headers, {}, auth);
        const res = await doFetch(joinUrl(m.baseUrl, substitute(read.path, {}, auth)), {
          method,
          headers,
        });
        if (res.status === 401 || res.status === 403) {
          throw new LatchError("provider_auth_failed", `${m.displayName} rejected the credentials.`);
        }
        if (!res.ok) {
          throw new LatchError("provider_rejected", `${m.displayName} read failed (HTTP ${res.status}).`);
        }
        const json = await res.json();
        const rows = getByPath(json, read.recordsPath);
        if (!Array.isArray(rows)) return [];
        const map = read.recordMap ?? DEFAULT_RECORD_MAP;
        return rows.map((raw) => {
          const row = raw as Record<string, unknown>;
          const record: DnsRecord = {
            type: String(row[map.type]) as DnsRecordType,
            host: toHost(String(row[map.host]), domain),
            value: String(row[map.value]),
            ttl: Number(row[map.ttl]) || 300,
          };
          if (map.priority && row[map.priority] != null) {
            record.priority = Number(row[map.priority]);
          }
          return record;
        });
      }
    : undefined;

  const adapter: ManifestAdapter = {
    manifest: m,
    capabilities,
    apply,
    dryRun,
    ...(readExisting ? { readExisting } : {}),
  };
  return adapter;
}

// ---------------------------------------------------------------------------
// registerManifestAdapter — validate, then register under the manifest id
// ---------------------------------------------------------------------------

export function registerManifestAdapter(
  m: AdapterManifest,
  opts?: ManifestAdapterOptions,
): ManifestAdapter {
  const check = validateManifest(m);
  if (!check.ok) {
    throw new LatchError(
      "unsupported",
      `invalid manifest "${(m as { id?: string }).id ?? "?"}": ${check.errors.join(" ")}`,
    );
  }
  const adapter = manifestAdapter(m, opts);
  registerAdapter(adapter);
  return adapter;
}
