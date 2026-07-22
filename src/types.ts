// Latch — canonical contract types for the DNS-automation engine.
//
// This is the single source of truth for the detect / connect / verify seam and
// the internal record shape. Per the repo's "transform once at the boundary" rule,
// external/wire shapes (Cloudflare API structs, Domain Connect params, Route 53
// change-sets, provider JSON) are converted to THESE types at the edge that
// receives them, then passed everywhere. No module deeper than an adapter should
// ever read a raw provider shape.
//
// Owned by the orchestrator. Lanes extend behavior in ./records, ./detect,
// ./providers, ./verify — they do not redefine these types.

// ---------------------------------------------------------------------------
// DNS records
// ---------------------------------------------------------------------------

/** DNS record types Latch can write. */
export type DnsRecordType = "A" | "AAAA" | "CNAME" | "CAA" | "MX" | "TXT" | "NS";

/**
 * Semantic purpose of a record. Drives email-DNS intelligence:
 * "spf"/"dkim"/"dmarc"/"mx" get the merge / chunk / clobber-guard / policy logic;
 * "site" is a plain A/AAAA/CNAME for pointing a domain at a published site.
 */
export type RecordPurpose =
  | "mx"
  | "spf"
  | "dkim"
  | "dmarc"
  | "site"
  | "verification"
  | "other";

/**
 * The canonical record shape. `value` may still contain dynamic variables
 * (see RecordVars) before the engine resolves them; `host` is "@" for the apex
 * or a subdomain label / FQDN.
 */
export interface DnsRecord {
  type: DnsRecordType;
  host: string;
  value: string;
  /** Minimum 300 (enforced by the engine). */
  ttl: number;
  /** MX only. */
  priority?: number;
  purpose?: RecordPurpose;
}

/**
 * Dynamic variables the engine substitutes into record `value`/`host` before write.
 * Uppercase + case-sensitive, matching the Entri-parity SDK contract.
 * `emailProviderSPF` resolves to the detected sending provider's include token.
 */
export interface RecordVars {
  DOMAIN: string;
  SUBDOMAIN: string;
  SLD: string;
  TLD: string;
  emailProviderSPF?: string;
}

// ---------------------------------------------------------------------------
// detect(domain)
// ---------------------------------------------------------------------------

/**
 * How Latch will attempt to write for this domain:
 *  - "cloudflare"       the domain's DNS host is Cloudflare (a CANDIDATE). connect()
 *                       confirms the zone is in OUR CF account before writing via the
 *                       CF API; a user-owned CF zone downgrades to domain_connect/manual.
 *  - "domain_connect"   provider advertises Domain Connect sync flow (no client secret)
 *  - "adapter:<id>"     a per-provider adapter (e.g. "adapter:route53")
 *  - "manual"           no automated path → polished manual fallback
 */
export type DetectMethod =
  | "cloudflare"
  | "domain_connect"
  | `adapter:${string}`
  | "manual";

export interface DetectResult {
  domain: string;
  /** Human name of the detected DNS host ("Cloudflare", "GoDaddy", …) or null. */
  dnsHost: string | null;
  method: DetectMethod;
  /** Present when the method needs an OAuth/consent redirect. */
  authUrl?: string;
  /** 0..1 confidence in the detection. */
  confidence: number;
  /** Zone is DNSSEC-signed → write only through a signing-aware host API. */
  dnssec: boolean;
  /** Domain resolves to a delegated zone. */
  registered: boolean;
  /** NS/apex points at a parking or for-sale service. */
  parked: boolean;
  /**
   * Present MX targets. Non-empty ⇒ a live mail provider already receives mail;
   * connect() must not silently clobber it (emits an `existing_mx` warning).
   */
  existingMx: string[];
  /** Authoritative nameservers observed for the zone. */
  nameservers: string[];
}

// ---------------------------------------------------------------------------
// connect(domain, records[])
// ---------------------------------------------------------------------------

/**
 * Proof that the caller controls the domain before Latch writes DNS to it.
 * Every write path establishes control by construction:
 *  - "cf_account_owned"  the zone is in OUR Cloudflare account (delegation was
 *                        proven when the zone was added — we can't hold a zone we
 *                        weren't delegated).
 *  - "provider_consent"  the user consented at their DNS host (Domain Connect / OAuth).
 *  - "user_credentials"  the caller supplied the host's own API/IAM credentials.
 *  - "dns_txt_challenge" a verification TXT the caller was asked to place was observed.
 * connect() records which proof applied; the public surface can require a specific
 * kind before writing (fails closed).
 */
export type ControlProofKind =
  | "cf_account_owned"
  | "provider_consent"
  | "user_credentials"
  | "dns_txt_challenge";

export interface ControlProof {
  kind: ControlProofKind;
  detail?: string;
}

export type ConnectStatus = "applied" | "manual_fallback" | "oauth_required";

export interface AppliedRecord extends DnsRecord {
  /** Provider's record id, when the adapter returns one. */
  recordId?: string;
}

export interface ManualRecord extends DnsRecord {
  /** Already merged / chunked / normalized — safe to display verbatim. */
  note?: string;
}

export type ConnectWarningCode =
  | "existing_mx"
  | "existing_dmarc"
  | "existing_spf"
  | "spf_lookup_limit"
  | "dnssec_unsigned_path"
  | "apex_cname"
  | "parked_domain"
  | "manual_fallback"
  | "provider_error";

export interface ConnectWarning {
  code: ConnectWarningCode;
  detail: string;
}

export interface ConnectResult {
  domain: string;
  status: ConnectStatus;
  applied: AppliedRecord[];
  /** Records the user must add by hand (manual_fallback) or confirm (e.g. MX clobber). */
  manual: ManualRecord[];
  /** Correlates verify() + webhooks. */
  jobId: string;
  /** Present when status === "oauth_required". */
  authUrl?: string;
  /** How control of the domain was established for this write (audit + policy). */
  controlProof?: ControlProof;
  warnings: ConnectWarning[];
}

// ---------------------------------------------------------------------------
// verify(domain, jobId?)
// ---------------------------------------------------------------------------

/**
 * Verification truth. "published" is the STRONG gate and requires an authoritative
 * signal (an owned-zone CF-API read-back, or a future authoritative resolver); public
 * DoH alone can never reach it, because DoH answers from a recursive cache, not the
 * zone's authoritative nameservers.
 *  - "published"    authoritative source confirms AND public resolvers agree (strong gate)
 *  - "confirmed"    confirmed across public resolvers but NOT authoritatively verified —
 *                   the terminal success state for a zone Latch cannot read authoritatively
 *                   (external domain, no owned read-back / sidecar). Honestly weaker than published.
 *  - "propagating"  confirmed by some resolvers but others still serving stale/absent answers
 *  - "pending"      not yet observed
 *  - "failed"       propagation timeout (72h) or a hard error
 */
export type VerifyStatus = "pending" | "published" | "confirmed" | "propagating" | "failed";

export interface RecordVerifyState {
  type: DnsRecordType;
  host: string;
  status: VerifyStatus;
}

export interface VerifyResult {
  domain: string;
  jobId?: string;
  status: VerifyStatus;
  records: RecordVerifyState[];
}

// ---------------------------------------------------------------------------
// Provider adapters
// ---------------------------------------------------------------------------

export type AdapterAuthKind =
  | "none"
  | "oauth"
  | "api_key"
  | "iam"
  | "domain_connect_sync";

export interface AdapterCapabilities {
  /** "cloudflare" | "route53" | "namecheap" | "domain-connect" | … */
  id: string;
  displayName: string;
  /** Can it write records without manual user steps? */
  automated: boolean;
  authKind: AdapterAuthKind;
  writesRecordTypes: DnsRecordType[];
  /** ALIAS / CNAME-flattening available at the apex? */
  supportsApex: boolean;
}

/**
 * Opaque credential bag, resolved at the boundary (secrets::resolver on the
 * sidecar, or worker env). The engine never inspects its internals.
 */
export interface AdapterAuth {
  [k: string]: unknown;
}

export interface AdapterApplyResult {
  applied: AppliedRecord[];
  manual: ManualRecord[];
}

export interface Adapter {
  capabilities(): AdapterCapabilities;
  /** Returns an authorize URL when the adapter needs interactive consent, else null. */
  authUrl?(domain: string, redirectUri: string): Promise<string | null>;
  /**
   * Read the zone's current records authoritatively — through the provider's own
   * API — so connect() can read-before-write for the SPF/DMARC merges and the MX
   * clobber-guard (public DoH is a stale recursive cache and must not seed a
   * read-modify-write). Optional: sync/manual adapters that cannot read omit this,
   * and connect() falls back to a DoH read (best-effort, flagged).
   */
  readExisting?(domain: string, auth?: AdapterAuth): Promise<DnsRecord[]>;
  /** Applies records. Throws on hard failure; records it cannot write fall to `manual`. */
  apply(
    domain: string,
    records: DnsRecord[],
    auth?: AdapterAuth,
  ): Promise<AdapterApplyResult>;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export type LatchErrorCode =
  | "unregistered_domain"
  | "not_delegated"
  | "provider_auth_failed"
  | "provider_rejected"
  | "unsupported"
  | "internal";

export class LatchError extends Error {
  readonly code: LatchErrorCode;
  constructor(code: LatchErrorCode, message: string) {
    super(message);
    this.name = "LatchError";
    this.code = code;
  }
}
