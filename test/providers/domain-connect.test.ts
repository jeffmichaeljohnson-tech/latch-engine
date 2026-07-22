import { describe, expect, it } from "vitest";
import {
  DomainConnectAdapter,
  domainConnectAdapter,
  makeDomainConnectAdapter,
} from "../../src/providers/domain-connect";

describe("DomainConnectAdapter.authUrl", () => {
  it("builds a correct sync-apply URL with providerId/serviceId path + vars", async () => {
    const adapter = makeDomainConnectAdapter({
      providerId: "GoDaddy",
      serviceId: "gbuild-email",
      urlSyncUX: "https://domainconnect.godaddy.com/sync/",
      vars: { SPF: "include:_spf.gbuild.app", MXHOST: "mx.gbuild.app" },
      state: "csrf-xyz",
    });

    const url = await adapter.authUrl("example.com", "gbuild://dns/callback");
    expect(url).not.toBeNull();
    const parsed = new URL(url as string);

    // Base + template path (trailing slash on urlSyncUX normalized away).
    expect(parsed.origin).toBe("https://domainconnect.godaddy.com");
    expect(parsed.pathname).toBe(
      "/sync/v2/domainTemplates/providers/GoDaddy/services/gbuild-email/apply",
    );
    expect(parsed.searchParams.get("domain")).toBe("example.com");
    expect(parsed.searchParams.get("SPF")).toBe("include:_spf.gbuild.app");
    expect(parsed.searchParams.get("MXHOST")).toBe("mx.gbuild.app");
    expect(parsed.searchParams.get("redirect_uri")).toBe("gbuild://dns/callback");
    expect(parsed.searchParams.get("state")).toBe("csrf-xyz");
  });

  it("percent-encodes provider/service path segments", async () => {
    const adapter = makeDomainConnectAdapter({
      providerId: "Provider Space",
      serviceId: "svc/weird",
      urlSyncUX: "https://sync.example.com",
    });
    const url = await adapter.authUrl("example.com", "gbuild://cb");
    expect(url).toContain("/providers/Provider%20Space/services/svc%2Fweird/apply");
  });

  it("returns null when unconfigured (the registered default)", async () => {
    const url = await domainConnectAdapter.authUrl("example.com", "gbuild://cb");
    expect(url).toBeNull();
  });
});

describe("DomainConnectAdapter.apply / capabilities", () => {
  it("writes nothing server-side (empty applied + manual)", async () => {
    const out = await new DomainConnectAdapter().apply();
    expect(out).toEqual({ applied: [], manual: [] });
  });

  it("advertises the sync auth kind and non-automated (consent) flow", () => {
    const caps = new DomainConnectAdapter().capabilities();
    expect(caps.id).toBe("domain-connect");
    expect(caps.authKind).toBe("domain_connect_sync");
    expect(caps.automated).toBe(false);
  });
});
