import { describe, expect, it } from "vitest";
import type {
  Adapter,
  AdapterApplyResult,
  DetectResult,
  DnsRecord,
} from "../../src/types";
import { LatchError } from "../../src/types";
import { CLOUDFLARE_CAPABILITIES } from "../../src/providers";
import { connect, type ConnectDeps } from "../../src/connect/connect";

function det(method: DetectResult["method"], extra: Partial<DetectResult> = {}): DetectResult {
  return {
    domain: "acme.com",
    dnsHost: null,
    method,
    confidence: 0.9,
    dnssec: false,
    registered: true,
    parked: false,
    existingMx: [],
    nameservers: [],
    ...extra,
  };
}

function fakeAdapter(opts: {
  existing?: DnsRecord[];
  onApply?: (records: DnsRecord[]) => AdapterApplyResult;
  throwOnApply?: Error;
}): Adapter {
  return {
    capabilities: () => CLOUDFLARE_CAPABILITIES,
    readExisting: async () => opts.existing ?? [],
    apply: async (_domain, records): Promise<AdapterApplyResult> => {
      if (opts.throwOnApply) throw opts.throwOnApply;
      if (opts.onApply) return opts.onApply(records);
      return { applied: records.map((r) => ({ ...r })), manual: [] };
    },
  };
}

describe("connect() orchestrator", () => {
  it("cloudflare-owned zone → writes via the CF adapter, records cf_account_owned proof", async () => {
    const adapter = fakeAdapter({});
    const deps: ConnectDeps = {
      getAdapter: (id) => (id === "cloudflare" ? adapter : undefined),
      resolveOwnedCloudflareZone: async () => ({ zoneId: "z", token: "t" }),
      newJobId: () => "job-1",
    };
    const res = await connect(
      { detect: det("cloudflare"), email: { subdomain: "agent", spfIncludes: ["include:_spf.resend.com"] } },
      deps,
    );
    expect(res.status).toBe("applied");
    expect(res.controlProof).toEqual({ kind: "cf_account_owned" });
    expect(res.jobId).toBe("job-1");
    expect(res.applied.some((r) => r.purpose === "spf" && r.host === "agent")).toBe(true);
  });

  it("reads existing records THROUGH the adapter and merges SPF before writing (P0-1)", async () => {
    const adapter = fakeAdapter({
      existing: [{ type: "TXT", host: "agent", value: "v=spf1 include:_spf.google.com ~all", ttl: 3600 }],
    });
    const deps: ConnectDeps = {
      getAdapter: () => adapter,
      resolveOwnedCloudflareZone: async () => ({ zoneId: "z", token: "t" }),
      newJobId: () => "j",
    };
    const res = await connect(
      { detect: det("cloudflare"), email: { subdomain: "agent", spfIncludes: ["include:_spf.resend.com"] } },
      deps,
    );
    const spf = res.applied.find((r) => r.purpose === "spf")!;
    expect(spf.value).toBe("v=spf1 include:_spf.google.com include:_spf.resend.com ~all");
  });

  it("Cloudflare NS but NOT in our account → manual fallback, no control proof (P0-3)", async () => {
    const deps: ConnectDeps = {
      getAdapter: () => fakeAdapter({}),
      resolveOwnedCloudflareZone: async () => null,
      readExistingViaDns: async () => [],
      newJobId: () => "j",
    };
    const res = await connect(
      { detect: det("cloudflare"), email: { subdomain: "agent", spfIncludes: [] } },
      deps,
    );
    expect(res.status).toBe("manual_fallback");
    expect(res.manual.length).toBeGreaterThan(0);
    expect(res.controlProof).toBeUndefined();
    expect(res.warnings.some((w) => w.code === "manual_fallback")).toBe(true);
  });

  it("domain_connect → oauth_required with the built sync-apply URL and provider_consent proof", async () => {
    const deps: ConnectDeps = {
      getAdapter: () => undefined,
      domainConnectConfig: () => ({
        providerId: "GoDaddy",
        serviceId: "gbuild-email",
        urlSyncUX: "https://dc.godaddy.com/sync",
      }),
      redirectUri: "gbuild://connector/callback/latch",
      readExistingViaDns: async () => [],
      newJobId: () => "j",
    };
    const res = await connect(
      { detect: det("domain_connect"), email: { subdomain: "agent", spfIncludes: [] } },
      deps,
    );
    expect(res.status).toBe("oauth_required");
    expect(res.authUrl).toContain("/v2/domainTemplates/providers/GoDaddy/services/gbuild-email/apply");
    expect(res.authUrl).toContain("redirect_uri=gbuild");
    expect(res.controlProof).toEqual({ kind: "provider_consent" });
  });

  it("route53 wired + creds → writes via the adapter, user_credentials proof", async () => {
    const r53 = fakeAdapter({});
    const deps: ConnectDeps = {
      getAdapter: (id) => (id === "route53" ? r53 : undefined),
      adapterAuth: (id) => (id === "route53" ? { accessKeyId: "a", secretAccessKey: "b", hostedZoneId: "z" } : undefined),
      readExistingViaDns: async () => [],
      newJobId: () => "j",
    };
    const res = await connect(
      { detect: det("adapter:route53"), email: { subdomain: "agent", spfIncludes: [] } },
      deps,
    );
    expect(res.status).toBe("applied");
    expect(res.controlProof).toEqual({ kind: "user_credentials" });
  });

  it("Namecheap is unwired in v1 → manual fallback", async () => {
    const res = await connect(
      { detect: det("adapter:namecheap"), email: { subdomain: "agent", spfIncludes: [] } },
      { getAdapter: () => undefined, readExistingViaDns: async () => [], newJobId: () => "j" },
    );
    expect(res.status).toBe("manual_fallback");
    expect(res.warnings.some((w) => w.detail.includes("namecheap"))).toBe(true);
  });

  it("manual detection → manual fallback carrying the prepared records", async () => {
    const res = await connect(
      { detect: det("manual"), email: { subdomain: "agent", spfIncludes: ["include:_spf.resend.com"] } },
      { getAdapter: () => undefined, readExistingViaDns: async () => [], newJobId: () => "j" },
    );
    expect(res.status).toBe("manual_fallback");
    expect(res.manual.some((r) => r.purpose === "spf")).toBe(true);
  });

  it("a provider hard-failure NEVER dead-ends — it degrades to manual fallback", async () => {
    const throwing = fakeAdapter({ throwOnApply: new LatchError("provider_auth_failed", "token rejected") });
    const deps: ConnectDeps = {
      getAdapter: (id) => (id === "cloudflare" ? throwing : undefined),
      resolveOwnedCloudflareZone: async () => ({ zoneId: "z", token: "t" }),
      readExistingViaDns: async () => [],
      newJobId: () => "j",
    };
    const res = await connect(
      { detect: det("cloudflare"), email: { subdomain: "agent", spfIncludes: [] } },
      deps,
    );
    expect(res.status).toBe("manual_fallback");
    expect(res.warnings.some((w) => w.code === "provider_error")).toBe(true);
    expect(res.manual.length).toBeGreaterThan(0);
  });

  it("honors a caller-supplied control proof", async () => {
    const deps: ConnectDeps = {
      getAdapter: () => fakeAdapter({}),
      resolveOwnedCloudflareZone: async () => ({ zoneId: "z", token: "t" }),
      newJobId: () => "j",
    };
    const res = await connect(
      {
        detect: det("cloudflare"),
        email: { subdomain: "agent", spfIncludes: [] },
        controlProof: { kind: "dns_txt_challenge", detail: "TXT observed" },
      },
      deps,
    );
    expect(res.controlProof).toEqual({ kind: "dns_txt_challenge", detail: "TXT observed" });
  });
});
