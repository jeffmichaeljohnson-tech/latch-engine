import { afterEach, describe, expect, it, vi } from "vitest";
import {
  CloudflareAdapter,
  readBack,
  CLOUDFLARE_CAPABILITIES,
} from "../../src/providers/cloudflare";
import { LatchError } from "../../src/types";
import type { DnsRecord } from "../../src/types";

const AUTH = { zoneId: "zone123", token: "cf-token-secret" };

/** The zone listing `apply` reads before it decides PUT vs POST. */
function cfList(records: Array<{ id: string; type: string; name: string }> = []): Response {
  return new Response(
    JSON.stringify({ success: true, errors: [], result: records }),
    { status: 200, headers: { "content-type": "application/json" } },
  );
}

/**
 * Wrap a write-only stub so it also answers the leading zone read.
 * `existing` seeds records already in the zone, which is what makes `apply`
 * choose PUT.
 */
function withZoneRead(
  existing: Array<{ id: string; type: string; name: string }>,
  onWrite: (input: string | URL, init?: RequestInit) => Promise<Response>,
) {
  // Routed on the request SHAPE, not on call order: the zone read is the only
  // GET, so this keeps working across mockClear() and repeated applies.
  return async (input: string | URL, init?: RequestInit) => {
    const method = init?.method ?? "GET";
    if (method === "GET") return cfList(existing);
    return onWrite(input, init);
  };
}

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
    const fetchMock = fetchFn(withZoneRead([], async () => cfOk("rec-abc")));
    vi.stubGlobal("fetch", fetchMock);

    const record: DnsRecord = {
      type: "TXT",
      host: "@",
      value: "v=spf1 include:example.com ~all",
      ttl: 300,
      purpose: "spf",
    };
    const out = await new CloudflareAdapter().apply("example.com", [record], AUTH);

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [url, init] = fetchMock.mock.calls[1]!;
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
    const fetchMock = fetchFn(withZoneRead([], async () => cfOk("mx-1")));
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
    const body = JSON.parse(fetchMock.mock.calls[1]![1]!.body as string);
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
    const body2 = JSON.parse(fetchMock.mock.calls[1]![1]!.body as string);
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
        withZoneRead([], async () =>
          new Response(
            JSON.stringify({
              success: false,
              errors: [{ code: 81057, message: "Record already exists." }],
              result: null,
            }),
            { status: 400 },
          ),
        ),
      ),
    );
    const record: DnsRecord = { type: "A", host: "@", value: "1.2.3.4", ttl: 300 };
    const out = await new CloudflareAdapter().apply("example.com", [record], AUTH);
    expect(out.applied).toHaveLength(0);
    expect(out.manual).toHaveLength(1);
    expect(out.manual[0]!.note).toContain("81057");
  });

  it("UPDATES a matching record instead of creating a second one", async () => {
    // The bug this pins: apply() used to POST unconditionally. The engine reads
    // the zone precisely so it can MERGE — mergeSpf folds our include into the
    // SPF already there and returns one record — and the writer then created
    // that merged record BESIDE the original. Two v=spf1 TXTs at the apex is an
    // RFC 7208 permerror: all mail fails. And the call returned "applied".
    const fetchMock = fetchFn(
      withZoneRead(
        [{ id: "existing-spf", type: "TXT", name: "example.com" }],
        async () => cfOk("existing-spf"),
      ),
    );
    vi.stubGlobal("fetch", fetchMock);

    const merged: DnsRecord = {
      type: "TXT",
      host: "@",
      value: "v=spf1 include:old.example include:new.example ~all",
      ttl: 300,
      purpose: "spf",
    };
    const out = await new CloudflareAdapter().apply("example.com", [merged], AUTH);

    const writes = fetchMock.mock.calls.filter(([, init]) => (init?.method ?? "GET") !== "GET");
    expect(writes).toHaveLength(1);
    const [url, init] = writes[0]!;
    expect(init!.method).toBe("PUT");
    expect(url).toBe(
      "https://api.cloudflare.com/client/v4/zones/zone123/dns_records/existing-spf",
    );
    expect(out.applied).toHaveLength(1);
    expect(out.manual).toHaveLength(0);
  });

  it("CREATES when nothing matches, so the upsert is not a blanket update", async () => {
    // The must-not-fire half. An adapter that only ever PUT would pass the test
    // above and be unable to add a record at all.
    const fetchMock = fetchFn(
      withZoneRead(
        [{ id: "unrelated", type: "A", name: "example.com" }],
        async () => cfOk("new-dmarc"),
      ),
    );
    vi.stubGlobal("fetch", fetchMock);

    const record: DnsRecord = {
      type: "TXT",
      host: "_dmarc",
      value: "v=DMARC1; p=none",
      ttl: 300,
      purpose: "dmarc",
    };
    await new CloudflareAdapter().apply("example.com", [record], AUTH);

    const writes = fetchMock.mock.calls.filter(([, init]) => (init?.method ?? "GET") !== "GET");
    expect(writes[0]![1]!.method).toBe("POST");
  });

  it("refuses to write into a zone it could not read", async () => {
    // Falling back to a blind create here would be the duplicate-SPF bug again,
    // one level quieter: a merge computed from an empty view of the zone.
    vi.stubGlobal(
      "fetch",
      fetchFn(async (_i, init) =>
        (init?.method ?? "GET") === "GET"
          ? new Response(JSON.stringify({ success: false, errors: [{ code: 1, message: "nope" }], result: null }),
              { status: 500, headers: { "content-type": "application/json" } })
          : cfOk("should-not-happen"),
      ),
    );
    const record: DnsRecord = { type: "A", host: "@", value: "1.2.3.4", ttl: 300 };
    await expect(new CloudflareAdapter().apply("example.com", [record], AUTH)).rejects.toThrow();
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
