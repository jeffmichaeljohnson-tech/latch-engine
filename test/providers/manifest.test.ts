import { afterEach, describe, expect, it, vi } from "vitest";
import {
  validateManifest,
  manifestAdapter,
  type AdapterManifest,
} from "../../src/providers/manifest";
import { LatchError } from "../../src/types";
import type { DnsRecord } from "../../src/types";

// A Cloudflare-shaped provider described purely as DATA. Trust is a CALLER option
// (manifestAdapter(m, { trusted: true })), never a manifest field.
function sampleManifest(): AdapterManifest {
  return {
    id: "acme-dns",
    displayName: "Acme DNS",
    authKind: "api_key",
    baseUrl: "https://api.acme.test/v1",
    capabilities: {
      writesRecordTypes: ["A", "AAAA", "CNAME", "MX", "TXT"],
      supportsApex: true,
      automated: true,
    },
    create: {
      path: "/zones/{auth:zoneId}/records",
      method: "POST",
      headers: { Authorization: "Bearer {auth:token}" },
      bodyTemplate: {
        type: "{type}",
        name: "{fqdn}",
        content: "{value}",
        ttl: "{ttl}",
        priority: "{priority}",
      },
    },
    read: {
      path: "/zones/{auth:zoneId}/records",
      method: "GET",
      headers: { Authorization: "Bearer {auth:token}" },
      recordsPath: "result",
      recordMap: { type: "type", host: "name", value: "content", ttl: "ttl", priority: "priority" },
    },
    responseIdPath: "result.id",
  };
}

const AUTH = { zoneId: "zone-42", token: "acme-secret" };

// A fetch-shaped mock so `.mock.calls[n]` is typed as [url, init].
function fetchFn(impl: (input: string | URL, init?: RequestInit) => Promise<Response>) {
  return vi.fn(impl);
}

function okJson(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

afterEach(() => vi.unstubAllGlobals());

describe("manifestAdapter.apply (trusted)", () => {
  it("maps a DnsRecord to the correct request body and parses the id", async () => {
    const fetchMock = fetchFn(async () => okJson({ result: { id: "rec-1" } }));
    vi.stubGlobal("fetch", fetchMock);

    const record: DnsRecord = {
      type: "TXT",
      host: "@",
      value: "v=spf1 include:acme.test ~all",
      ttl: 300,
      purpose: "spf",
    };
    const out = await manifestAdapter(sampleManifest(), { trusted: true }).apply("example.com", [record], AUTH);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]! as [string, RequestInit];
    expect(url).toBe("https://api.acme.test/v1/zones/zone-42/records");
    expect(init.method).toBe("POST");
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer acme-secret");
    expect((init.headers as Record<string, string>)["Content-Type"]).toBe("application/json");

    const body = JSON.parse(init.body as string);
    // priority dropped for a non-MX record; ttl stays a number.
    expect(body).toEqual({
      type: "TXT",
      name: "example.com",
      content: "v=spf1 include:acme.test ~all",
      ttl: 300,
    });
    expect(typeof body.ttl).toBe("number");

    expect(out.applied).toHaveLength(1);
    expect(out.applied[0]!.recordId).toBe("rec-1");
    expect(out.manual).toHaveLength(0);
  });

  it("builds an FQDN for a subdomain and keeps MX priority as a number", async () => {
    const fetchMock = fetchFn(async () => okJson({ result: { id: "mx-1" } }));
    vi.stubGlobal("fetch", fetchMock);

    const record: DnsRecord = {
      type: "MX",
      host: "mail",
      value: "mx.acme.test",
      ttl: 3600,
      priority: 10,
      purpose: "mx",
    };
    await manifestAdapter(sampleManifest(), { trusted: true }).apply("example.com", [record], AUTH);
    const body = JSON.parse((fetchMock.mock.calls[0]![1] as RequestInit).body as string);
    expect(body.name).toBe("mail.example.com");
    expect(body.priority).toBe(10);
    expect(typeof body.priority).toBe("number");
  });

  it("routes a rejected record to manual and throws on 403", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => okJson({ error: "exists" }, 400)));
    const record: DnsRecord = { type: "A", host: "@", value: "1.2.3.4", ttl: 300 };
    const rejected = await manifestAdapter(sampleManifest(), { trusted: true }).apply("example.com", [record], AUTH);
    expect(rejected.applied).toHaveLength(0);
    expect(rejected.manual).toHaveLength(1);

    vi.stubGlobal("fetch", vi.fn(async () => new Response("no", { status: 403 })));
    await expect(
      manifestAdapter(sampleManifest(), { trusted: true }).apply("example.com", [record], AUTH),
    ).rejects.toMatchObject({ code: "provider_auth_failed" });
  });

  it("throws a hard auth failure when a required auth placeholder is missing", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => okJson({ result: { id: "x" } })));
    const record: DnsRecord = { type: "A", host: "@", value: "1.2.3.4", ttl: 300 };
    await expect(
      manifestAdapter(sampleManifest(), { trusted: true }).apply("example.com", [record], { token: "t" }),
    ).rejects.toMatchObject({ code: "provider_auth_failed" });
  });
});

describe("safety gate — untrusted manifest", () => {
  it("apply() throws when the caller did not grant trust, WITHOUT touching fetch", async () => {
    const fetchMock = fetchFn(async () => okJson({ result: { id: "x" } }));
    vi.stubGlobal("fetch", fetchMock);

    // No { trusted: true } option → untrusted → apply() must refuse before any fetch.
    const record: DnsRecord = { type: "A", host: "@", value: "1.2.3.4", ttl: 300 };
    await expect(
      manifestAdapter(sampleManifest()).apply("example.com", [record], AUTH),
    ).rejects.toBeInstanceOf(LatchError);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("trust set via a self-asserted manifest field is IGNORED (provenance-based only)", async () => {
    const fetchMock = fetchFn(async () => okJson({ result: { id: "x" } }));
    vi.stubGlobal("fetch", fetchMock);
    // A manifest can't bless itself: an extra `trusted:true` on the JSON does nothing.
    const selfBlessed = { ...sampleManifest(), trusted: true } as AdapterManifest;
    const record: DnsRecord = { type: "A", host: "@", value: "1.2.3.4", ttl: 300 };
    await expect(
      manifestAdapter(selfBlessed).apply("example.com", [record], AUTH),
    ).rejects.toMatchObject({ code: "unsupported" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("an untrusted manifest advertises automated:false; a caller-trusted one advertises true", () => {
    expect(manifestAdapter(sampleManifest()).capabilities().automated).toBe(false);
    expect(manifestAdapter(sampleManifest(), { trusted: true }).capabilities().automated).toBe(true);
  });

  it("dryRun renders the would-be requests for an untrusted manifest WITHOUT fetching", () => {
    const fetchMock = fetchFn(async () => okJson({ result: { id: "x" } }));
    vi.stubGlobal("fetch", fetchMock);

    const untrusted = manifestAdapter(sampleManifest());
    const record: DnsRecord = { type: "A", host: "@", value: "1.2.3.4", ttl: 300 };
    const reqs = untrusted.dryRun("example.com", [record], AUTH);

    expect(fetchMock).not.toHaveBeenCalled();
    expect(reqs).toHaveLength(1);
    expect(reqs[0]!.url).toBe("https://api.acme.test/v1/zones/zone-42/records");
    expect(reqs[0]!.method).toBe("POST");
    expect(JSON.parse(reqs[0]!.body)).toEqual({
      type: "A",
      name: "example.com",
      content: "1.2.3.4",
      ttl: 300,
    });
  });
});

describe("validateManifest", () => {
  it("accepts a well-formed manifest", () => {
    expect(validateManifest(sampleManifest())).toEqual({ ok: true });
  });

  it("rejects a DELETE method anywhere", () => {
    const m = sampleManifest();
    m.create.method = "DELETE";
    const res = validateManifest(m);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.errors.some((e) => e.includes("DELETE"))).toBe(true);

    const m2 = sampleManifest();
    m2.read!.method = "DELETE";
    const res2 = validateManifest(m2);
    expect(res2.ok).toBe(false);
    if (!res2.ok) expect(res2.errors.some((e) => e.includes("DELETE"))).toBe(true);
  });

  it("rejects a non-http(s) baseUrl", () => {
    for (const baseUrl of ["ftp://acme.test", "file:///etc/passwd", "javascript:alert(1)", "not-a-url"]) {
      const res = validateManifest({ ...sampleManifest(), baseUrl });
      expect(res.ok).toBe(false);
      if (!res.ok) expect(res.errors.some((e) => e.includes("baseUrl"))).toBe(true);
    }
  });

  it("rejects an unknown placeholder in the body template", () => {
    const m = sampleManifest();
    (m.create.bodyTemplate as Record<string, unknown>).evil = "{__proto__}";
    const res = validateManifest(m);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.errors.some((e) => e.includes("unknown placeholder"))).toBe(true);
  });

  it("rejects an auth placeholder inside the body template (record data only)", () => {
    const m = sampleManifest();
    (m.create.bodyTemplate as Record<string, unknown>).token = "{auth:token}";
    const res = validateManifest(m);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.errors.some((e) => e.includes("not allowed"))).toBe(true);
  });

  it("rejects a missing create block and a bad authKind", () => {
    const res = validateManifest({ ...sampleManifest(), create: undefined, authKind: "nope" });
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.errors.some((e) => e.includes("create"))).toBe(true);
      expect(res.errors.some((e) => e.includes("authKind"))).toBe(true);
    }
  });
});

describe("manifestAdapter.readExisting", () => {
  it("maps a provider list response to canonical DnsRecord[]", async () => {
    const rows = [
      { id: "1", type: "TXT", name: "example.com", content: "v=spf1 -all", ttl: 300 },
      { id: "2", type: "MX", name: "example.com", content: "mx.acme.test", ttl: 3600, priority: 5 },
      { id: "3", type: "CNAME", name: "www.example.com", content: "target.acme.test", ttl: 300 },
    ];
    const fetchMock = fetchFn(async () => okJson({ result: rows }));
    vi.stubGlobal("fetch", fetchMock);

    const adapter = manifestAdapter(sampleManifest());
    const out = await adapter.readExisting!("example.com", AUTH);

    const [url] = fetchMock.mock.calls[0]! as [string, RequestInit];
    expect(url).toBe("https://api.acme.test/v1/zones/zone-42/records");
    expect(out).toEqual([
      { type: "TXT", host: "@", value: "v=spf1 -all", ttl: 300 },
      { type: "MX", host: "@", value: "mx.acme.test", ttl: 3600, priority: 5 },
      { type: "CNAME", host: "www", value: "target.acme.test", ttl: 300 },
    ]);
  });
});

describe("DELETE is unreachable by construction", () => {
  it("no rendered request across every record type ever carries a DELETE method", () => {
    const adapter = manifestAdapter(sampleManifest());
    const records: DnsRecord[] = [
      { type: "A", host: "@", value: "1.2.3.4", ttl: 300 },
      { type: "AAAA", host: "@", value: "::1", ttl: 300 },
      { type: "CNAME", host: "www", value: "t.acme.test", ttl: 300 },
      { type: "MX", host: "@", value: "mx.acme.test", ttl: 300, priority: 10 },
      { type: "TXT", host: "@", value: "hello", ttl: 300 },
    ];
    for (const req of adapter.dryRun("example.com", records, AUTH)) {
      expect(req.method).not.toBe("DELETE");
      expect(req.method).toBe("POST");
    }
  });

  it("the interpreter refuses even if a DELETE method slips past validation", () => {
    // Bypass validateManifest to prove the runtime guard is independent.
    const rogue = { ...sampleManifest(), create: { ...sampleManifest().create, method: "DELETE" } };
    const adapter = manifestAdapter(rogue);
    const record: DnsRecord = { type: "A", host: "@", value: "1.2.3.4", ttl: 300 };
    expect(() => adapter.dryRun("example.com", [record], AUTH)).toThrow(LatchError);
  });
});
