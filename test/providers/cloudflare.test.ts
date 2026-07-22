import { afterEach, describe, expect, it, vi } from "vitest";
import {
  CloudflareAdapter,
  readBack,
  CLOUDFLARE_CAPABILITIES,
} from "../../src/providers/cloudflare";
import { LatchError } from "../../src/types";
import type { DnsRecord } from "../../src/types";

const AUTH = { zoneId: "zone123", token: "cf-token-secret" };

function cfOk(id: string): Response {
  return new Response(
    JSON.stringify({ success: true, errors: [], result: { id } }),
    { status: 200, headers: { "content-type": "application/json" } },
  );
}

// A fetch-shaped mock so `.mock.calls[n]` is typed as [url, init].
function fetchFn(impl: (input: string | URL, init?: RequestInit) => Promise<Response>) {
  return vi.fn(impl);
}

afterEach(() => vi.unstubAllGlobals());

describe("CloudflareAdapter.apply", () => {
  it("maps a record to a CF DNS create and parses the returned id", async () => {
    const fetchMock = fetchFn(async () => cfOk("rec-abc"));
    vi.stubGlobal("fetch", fetchMock);

    const record: DnsRecord = {
      type: "TXT",
      host: "@",
      value: "v=spf1 include:example.com ~all",
      ttl: 300,
      purpose: "spf",
    };
    const out = await new CloudflareAdapter().apply("example.com", [record], AUTH);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe(
      "https://api.cloudflare.com/client/v4/zones/zone123/dns_records",
    );
    expect(init!.method).toBe("POST");
    expect((init!.headers as Record<string, string>).Authorization).toBe(
      "Bearer cf-token-secret",
    );
    const body = JSON.parse(init!.body as string);
    expect(body).toEqual({
      type: "TXT",
      name: "example.com",
      content: "v=spf1 include:example.com ~all",
      ttl: 300,
    });

    expect(out.applied).toHaveLength(1);
    expect(out.applied[0]!.recordId).toBe("rec-abc");
    expect(out.manual).toHaveLength(0);
  });

  it("builds an FQDN for a subdomain host and includes MX priority", async () => {
    const fetchMock = fetchFn(async () => cfOk("mx-1"));
    vi.stubGlobal("fetch", fetchMock);

    const record: DnsRecord = {
      type: "MX",
      host: "@",
      value: "mx.example.net",
      ttl: 3600,
      priority: 10,
      purpose: "mx",
    };
    await new CloudflareAdapter().apply("example.com", [record], AUTH);
    const body = JSON.parse(fetchMock.mock.calls[0]![1]!.body as string);
    expect(body.name).toBe("example.com");
    expect(body.priority).toBe(10);

    const record2: DnsRecord = {
      type: "CNAME",
      host: "mail",
      value: "target.example.net",
      ttl: 300,
    };
    fetchMock.mockClear();
    await new CloudflareAdapter().apply("example.com", [record2], AUTH);
    const body2 = JSON.parse(fetchMock.mock.calls[0]![1]!.body as string);
    expect(body2.name).toBe("mail.example.com");
  });

  it("throws provider_auth_failed on 403", async () => {
    vi.stubGlobal(
      "fetch",
      fetchFn(async () => new Response("forbidden", { status: 403 })),
    );
    const record: DnsRecord = { type: "A", host: "@", value: "1.2.3.4", ttl: 300 };
    await expect(
      new CloudflareAdapter().apply("example.com", [record], AUTH),
    ).rejects.toMatchObject({ code: "provider_auth_failed" });
  });

  it("routes a single rejected record to manual (dumb writer)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              success: false,
              errors: [{ code: 81057, message: "Record already exists." }],
              result: null,
            }),
            { status: 400 },
          ),
      ),
    );
    const record: DnsRecord = { type: "A", host: "@", value: "1.2.3.4", ttl: 300 };
    const out = await new CloudflareAdapter().apply("example.com", [record], AUTH);
    expect(out.applied).toHaveLength(0);
    expect(out.manual).toHaveLength(1);
    expect(out.manual[0]!.note).toContain("81057");
  });

  it("requires zoneId + token", async () => {
    const record: DnsRecord = { type: "A", host: "@", value: "1.2.3.4", ttl: 300 };
    await expect(
      new CloudflareAdapter().apply("example.com", [record], {}),
    ).rejects.toBeInstanceOf(LatchError);
  });
});

describe("readBack", () => {
  it("lists records by type and name and returns the result array", async () => {
    const rows = [{ id: "r1", type: "TXT", name: "example.com", content: "x", ttl: 300 }];
    const fetchMock = fetchFn(
      async () =>
        new Response(JSON.stringify({ success: true, errors: [], result: rows }), {
          status: 200,
        }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const record: DnsRecord = { type: "TXT", host: "mail.example.com", value: "x", ttl: 300 };
    const result = await readBack("zone123", "cf-token-secret", record);

    const url = String(fetchMock.mock.calls[0]![0]);
    expect(url).toContain("/zones/zone123/dns_records?");
    expect(url).toContain("type=TXT");
    expect(url).toContain("name=mail.example.com");
    expect(result).toEqual(rows);
  });

  it("omits the name filter for the apex host", async () => {
    const fetchMock = fetchFn(
      async () =>
        new Response(JSON.stringify({ success: true, errors: [], result: [] }), {
          status: 200,
        }),
    );
    vi.stubGlobal("fetch", fetchMock);
    await readBack("zone123", "tok", { type: "A", host: "@", value: "1.2.3.4", ttl: 300 });
    const url = String(fetchMock.mock.calls[0]![0]);
    expect(url).toContain("type=A");
    expect(url).not.toContain("name=");
  });
});

describe("capabilities", () => {
  it("advertises apex support and api_key auth", () => {
    expect(CLOUDFLARE_CAPABILITIES.supportsApex).toBe(true);
    expect(CLOUDFLARE_CAPABILITIES.authKind).toBe("api_key");
    expect(CLOUDFLARE_CAPABILITIES.automated).toBe(true);
  });
});
