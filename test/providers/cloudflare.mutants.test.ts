// Latch — Cloudflare adapter: mutation-hardening tests.
//
// Companion to cloudflare.test.ts. That file pins the happy paths and the
// upsert bug; this one closes the mutants that survived it — mostly the
// read side (readExisting / toDnsRecord / toHost), the readBack error paths,
// the per-write auth failure inside apply(), and the argument/guard details
// (optional-chaining on auth, the || vs && in every guard, the exact error
// codes and messages). Each test says WHICH defect it prevents, and every
// group carries a negative control so a function that always returns the
// positive answer cannot pass.
//
// No test performs a real network call: fetch is stubbed for every case.

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  CloudflareAdapter,
  readBack,
  CLOUDFLARE_CAPABILITIES,
} from "../../src/providers/cloudflare";
import { LatchError } from "../../src/types";
import type { DnsRecord } from "../../src/types";

const AUTH = { zoneId: "zone123", token: "cf-token-secret" };
const BASE = "https://api.cloudflare.com/client/v4";

type FetchImpl = (input: string | URL, init?: RequestInit) => Promise<Response>;

function fetchFn(impl: FetchImpl) {
  return vi.fn(impl);
}

/** A Cloudflare-shaped JSON envelope. */
function cfEnvelope(
  result: unknown,
  opts?: { success?: boolean; errors?: Array<{ code: number; message: string }>; status?: number },
): Response {
  return new Response(
    JSON.stringify({
      success: opts?.success ?? true,
      errors: opts?.errors ?? [],
      result,
    }),
    { status: opts?.status ?? 200, headers: { "content-type": "application/json" } },
  );
}

/**
 * Route apply()'s two calls by SHAPE, not by order: the leading zone read is
 * the only GET. `listResult` seeds what the zone read returns; `onWrite`
 * answers the PUT/POST.
 */
function withZoneRead(
  listResult: Array<{ id: string; type: string; name: string }>,
  onWrite: FetchImpl,
): FetchImpl {
  return async (input, init) => {
    const method = init?.method ?? "GET";
    if (method === "GET") return cfEnvelope(listResult);
    return onWrite(input, init);
  };
}

function headersOf(init?: RequestInit): Record<string, string> {
  return (init?.headers ?? {}) as Record<string, string>;
}

afterEach(() => vi.unstubAllGlobals());

// ---------------------------------------------------------------------------
// readAuth — reached through every public method. Not exported, so exercised
// via apply(). (src lines 29-39)
// ---------------------------------------------------------------------------
describe("readAuth (via apply)", () => {
  const record: DnsRecord = { type: "A", host: "@", value: "1.2.3.4", ttl: 300 };

  it("throws a LatchError (not a TypeError) when auth is entirely absent", async () => {
    // Prevents dropping the optional chaining on `auth?.["zoneId"]` /
    // `auth?.["token"]`: without it, undefined auth throws a raw TypeError
    // instead of the domain error, and callers can no longer catch it as one.
    // A real network call must never happen here either.
    const fetchMock = fetchFn(async () => cfEnvelope([]));
    vi.stubGlobal("fetch", fetchMock);

    const err = await new CloudflareAdapter()
      .apply("example.com", [record])
      .then(() => null)
      .catch((e) => e);

    expect(err).toBeInstanceOf(LatchError);
    expect(err.code).toBe("provider_auth_failed");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects when ONLY the token is missing", async () => {
    // Prevents `||` -> `&&` on the guard: with `&&`, a present zoneId makes the
    // whole condition false and a token-less write proceeds to the network.
    const fetchMock = fetchFn(async () => cfEnvelope([]));
    vi.stubGlobal("fetch", fetchMock);
    await expect(
      new CloudflareAdapter().apply("example.com", [record], { zoneId: "z" }),
    ).rejects.toMatchObject({ code: "provider_auth_failed" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects when ONLY the zoneId is missing", async () => {
    // Prevents mutating the zoneId sub-condition to `false` (which would let a
    // zoneId-less config through). Paired with the token case above so neither
    // operand can be silently disabled.
    const fetchMock = fetchFn(async () => cfEnvelope([]));
    vi.stubGlobal("fetch", fetchMock);
    await expect(
      new CloudflareAdapter().apply("example.com", [record], { token: "t" }),
    ).rejects.toMatchObject({ code: "provider_auth_failed" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("carries the exact error code and a message naming what auth needs", async () => {
    // Prevents blanking the "provider_auth_failed" code or the human message
    // to "" — an empty code/message is a silently useless error.
    const err = (await new CloudflareAdapter()
      .apply("example.com", [record], {})
      .catch((e) => e)) as LatchError;
    expect(err.code).toBe("provider_auth_failed");
    expect(err.message).toContain("zoneId");
    expect(err.message.length).toBeGreaterThan(0);
  });

  it("NEGATIVE CONTROL: a fully-valid auth does not throw from readAuth", async () => {
    // If any guard mutant flipped to "always throw", this would fail. Proves the
    // rejections above come from missing fields, not from a broken accept path.
    const fetchMock = fetchFn(withZoneRead([], async () => cfEnvelope({ id: "ok" })));
    vi.stubGlobal("fetch", fetchMock);
    const out = await new CloudflareAdapter().apply("example.com", [record], AUTH);
    expect(out.applied).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// toName — via apply().body.name. (src lines 42-46)
// ---------------------------------------------------------------------------
describe("toName (via apply body)", () => {
  async function nameFor(host: string): Promise<string> {
    const fetchMock = fetchFn(withZoneRead([], async () => cfEnvelope({ id: "x" })));
    vi.stubGlobal("fetch", fetchMock);
    await new CloudflareAdapter().apply(
      "example.com",
      [{ type: "A", host, value: "1.2.3.4", ttl: 300 }],
      AUTH,
    );
    return JSON.parse(fetchMock.mock.calls[1]![1]!.body as string).name;
  }

  it('maps the "@" apex to the bare domain', async () => {
    // Prevents forcing the apex branch to false: "@" must not become "@.example.com".
    expect(await nameFor("@")).toBe("example.com");
  });

  it('maps an empty host "" to the bare domain', async () => {
    // Prevents the `host === ""` literal being swapped (e.g. to "Stryker was
    // here!"): an empty host must still resolve to the apex, not `.example.com`.
    expect(await nameFor("")).toBe("example.com");
  });

  it("leaves a host that already equals the domain untouched", async () => {
    // Prevents `||` -> `&&` and the `host === domain` branch flipping to false:
    // the bare domain must not be doubled into "example.com.example.com".
    expect(await nameFor("example.com")).toBe("example.com");
  });

  it("leaves an already-qualified subdomain untouched (endsWith, not startsWith)", async () => {
    // Prevents endsWith -> startsWith on the FQDN check: an FQDN would otherwise
    // be re-suffixed into "mail.example.com.example.com".
    expect(await nameFor("mail.example.com")).toBe("mail.example.com");
  });

  it("NEGATIVE CONTROL: a bare label IS qualified with the domain", async () => {
    // If toName always returned the input, the four cases above would all pass
    // vacuously. A short label must gain the suffix.
    expect(await nameFor("mail")).toBe("mail.example.com");
  });
});

// ---------------------------------------------------------------------------
// toCfBody — MX priority gate. (src lines 56-67, esp. line 63)
// ---------------------------------------------------------------------------
describe("toCfBody MX-priority gate (via apply body)", () => {
  async function bodyFor(record: DnsRecord) {
    const fetchMock = fetchFn(withZoneRead([], async () => cfEnvelope({ id: "x" })));
    vi.stubGlobal("fetch", fetchMock);
    await new CloudflareAdapter().apply("example.com", [record], AUTH);
    return JSON.parse(fetchMock.mock.calls[1]![1]!.body as string);
  }

  it("includes priority for an MX record", async () => {
    // Prevents the whole `if` collapsing to false: MX priority must be sent.
    const body = await bodyFor({ type: "MX", host: "@", value: "mx.example.net", ttl: 300, priority: 5 });
    expect(body.priority).toBe(5);
  });

  it("NEGATIVE CONTROL: does NOT attach priority to a non-MX record that carries one", async () => {
    // Prevents `&&` -> `||` and the condition being forced true: an A record
    // with a stray priority must NOT ship a priority to the DNS API.
    const body = await bodyFor({
      type: "A",
      host: "@",
      value: "1.2.3.4",
      ttl: 300,
      priority: 42 as unknown as number,
    });
    expect(body.priority).toBeUndefined();
    expect("priority" in body).toBe(false);
  });

  it("omits priority for an MX record with no numeric priority", async () => {
    // The other half of the `&&`: type is MX but priority is absent -> omit it.
    const body = await bodyFor({ type: "MX", host: "@", value: "mx.example.net", ttl: 300 });
    expect("priority" in body).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// readExisting — completely uncovered before. Exercises readAuth, the guard,
// the map, plus toDnsRecord/toHost. (src lines 133-146, 79-95)
// ---------------------------------------------------------------------------
describe("readExisting", () => {
  function stubList(
    result: unknown,
    opts?: { success?: boolean; errors?: Array<{ code: number; message: string }>; status?: number },
  ) {
    const fetchMock = fetchFn(async () => cfEnvelope(result, opts));
    vi.stubGlobal("fetch", fetchMock);
    return fetchMock;
  }

  it("reads the zone with a Bearer header and the per_page=100 URL", async () => {
    // Prevents blanking the fetch URL/options or the Authorization header
    // (the request would then hit "" or omit the token). Also proves the read
    // path is used at all.
    const fetchMock = stubList([]);
    await new CloudflareAdapter().readExisting("example.com", AUTH);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe(`${BASE}/zones/zone123/dns_records?per_page=100`);
    expect(init!.method ?? "GET").toBe("GET");
    expect(headersOf(init).Authorization).toBe("Bearer cf-token-secret");
  });

  it("maps CF records back to canonical DnsRecords (apex, subdomain, MX)", async () => {
    // Prevents toDnsRecord's object literal being emptied and the .map callback
    // being replaced with () => undefined. Each field is asserted, so an empty
    // record or an array of undefined fails.
    const fetchMock = stubList([
      { id: "a1", type: "A", name: "example.com", content: "1.2.3.4", ttl: 300 },
      { id: "c1", type: "CNAME", name: "mail.example.com", content: "target.net", ttl: 3600 },
      { id: "m1", type: "MX", name: "example.com", content: "mx.example.net", ttl: 300, priority: 10 },
    ]);
    const out = await new CloudflareAdapter().readExisting("example.com", AUTH);
    expect(out).toEqual([
      { type: "A", host: "@", value: "1.2.3.4", ttl: 300 },
      { type: "CNAME", host: "mail", value: "target.net", ttl: 3600 },
      { type: "MX", host: "@", value: "mx.example.net", ttl: 300, priority: 10 },
    ]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("folds both apex forms (bare and trailing-dot) to \"@\"", async () => {
    // toHost line 80: covers `name === domain` and `name === `${domain}.`` and
    // the `||` between them. Both must fold to the apex, not stay verbatim.
    stubList([
      { id: "d1", type: "TXT", name: "example.com", content: "bare", ttl: 300 },
      { id: "d2", type: "TXT", name: "example.com.", content: "dotted", ttl: 300 },
    ]);
    const out = await new CloudflareAdapter().readExisting("example.com", AUTH);
    expect(out.map((r) => r.host)).toEqual(["@", "@"]);
  });

  it("NEGATIVE CONTROL: a name that does not belong to the zone is returned verbatim", async () => {
    // toHost line 81: prevents endsWith -> startsWith / endsWith("") (always
    // true) / slicing an unrelated name. "other.org" must not be sliced to "".
    stubList([{ id: "o1", type: "A", name: "other.org", content: "9.9.9.9", ttl: 300 }]);
    const out = await new CloudflareAdapter().readExisting("example.com", AUTH);
    expect(out[0]!.host).toBe("other.org");
  });

  it("slices EXACTLY the host label from a subdomain (length math)", async () => {
    // toHost line 81 arithmetic: prevents `domain.length + 1` -> `- 1` and the
    // unary minus flipping to plus. Off-by-one would yield "mail" + a leftover
    // char or a from-the-start slice.
    stubList([{ id: "s1", type: "CNAME", name: "mail.example.com", content: "t.net", ttl: 300 }]);
    const out = await new CloudflareAdapter().readExisting("example.com", AUTH);
    expect(out[0]!.host).toBe("mail");
  });

  it("copies MX priority but NEGATIVE CONTROL: never copies priority onto a non-MX record", async () => {
    // toDnsRecord line 93: prevents `&&` -> `||` (an A record with a stray
    // priority would gain a priority) and the type check flipping.
    stubList([
      { id: "m1", type: "MX", name: "example.com", content: "mx.net", ttl: 300, priority: 20 },
      { id: "a1", type: "A", name: "example.com", content: "1.2.3.4", ttl: 300, priority: 99 },
    ]);
    const out = await new CloudflareAdapter().readExisting("example.com", AUTH);
    expect(out[0]!.priority).toBe(20);
    expect("priority" in out[1]!).toBe(false);
  });

  it("throws provider_auth_failed on 401 and on 403", async () => {
    // Prevents the auth guard collapsing (line 138) and the 401/403 equality
    // being disabled. Both statuses must map to the auth error.
    for (const status of [401, 403]) {
      stubList([], { status });
      await expect(
        new CloudflareAdapter().readExisting("example.com", AUTH),
      ).rejects.toMatchObject({ code: "provider_auth_failed" });
    }
  });

  it("throws provider_rejected when success is false", async () => {
    // Line 142 guard: a false `success` must reject, not return records.
    stubList(null, { success: false, errors: [{ code: 7003, message: "no route" }], status: 200 });
    await expect(
      new CloudflareAdapter().readExisting("example.com", AUTH),
    ).rejects.toMatchObject({ code: "provider_rejected" });
  });

  it("throws provider_rejected when result is null even though success is true", async () => {
    // Line 142 `!json.result` term (and its boolean-literal mutant): a null
    // result cannot be mapped, so it must reject.
    stubList(null, { success: true });
    await expect(
      new CloudflareAdapter().readExisting("example.com", AUTH),
    ).rejects.toMatchObject({ code: "provider_rejected" });
  });

  it("throws provider_rejected on a non-2xx body even if success is true (inner OR)", async () => {
    // Line 142 `!res.ok` term and the INNER `||` -> `&&`: a 500 with success:true
    // must still reject. The && mutant would treat this as a good read.
    stubList([], { status: 500, success: true });
    await expect(
      new CloudflareAdapter().readExisting("example.com", AUTH),
    ).rejects.toMatchObject({ code: "provider_rejected" });
  });

  it("rejects a success:false body that oddly still carries a result (outer OR)", async () => {
    // Line 142 OUTER `||` -> `&&`: with `&&`, a false success + present result
    // would be accepted. The source makes no such contract, so it must reject.
    stubList([{ id: "x", type: "A", name: "example.com", content: "1.2.3.4", ttl: 300 }], {
      success: false,
      status: 200,
    });
    await expect(
      new CloudflareAdapter().readExisting("example.com", AUTH),
    ).rejects.toMatchObject({ code: "provider_rejected" });
  });
});

// ---------------------------------------------------------------------------
// apply — the per-write auth failure inside the loop (line 206), reached only
// after the zone read SUCCEEDS. The happy paths live in cloudflare.test.ts.
// ---------------------------------------------------------------------------
describe("apply per-write auth + rejection", () => {
  const record: DnsRecord = { type: "A", host: "@", value: "1.2.3.4", ttl: 300 };

  it("throws provider_auth_failed when the WRITE returns 401 (zone read was fine)", async () => {
    // Line 206: distinct from the zone-read auth check on line 175. The GET
    // succeeds; only the POST is unauthorized.
    let getCount = 0;
    const fetchMock = fetchFn(async (_i, init) => {
      if ((init?.method ?? "GET") === "GET") {
        getCount++;
        return cfEnvelope([]);
      }
      return new Response("no", { status: 401 });
    });
    vi.stubGlobal("fetch", fetchMock);
    await expect(
      new CloudflareAdapter().apply("example.com", [record], AUTH),
    ).rejects.toMatchObject({ code: "provider_auth_failed" });
    expect(getCount).toBe(1); // the read really did succeed first
  });

  it("also throws provider_auth_failed when the WRITE returns 403", async () => {
    // The 403 half of the line-206 equality, and the `||` there.
    const fetchMock = fetchFn(
      withZoneRead([], async () => new Response("no", { status: 403 })),
    );
    vi.stubGlobal("fetch", fetchMock);
    await expect(
      new CloudflareAdapter().apply("example.com", [record], AUTH),
    ).rejects.toMatchObject({ code: "provider_auth_failed" });
  });

  it("sends Content-Type: application/json on the write", async () => {
    // Prevents blanking the "Content-Type" header value: a CF create without it
    // would be mis-parsed.
    const fetchMock = fetchFn(withZoneRead([], async () => cfEnvelope({ id: "r1" })));
    vi.stubGlobal("fetch", fetchMock);
    await new CloudflareAdapter().apply("example.com", [record], AUTH);
    expect(headersOf(fetchMock.mock.calls[1]![1]!)["Content-Type"]).toBe("application/json");
    expect(headersOf(fetchMock.mock.calls[1]![1]!).Authorization).toBe("Bearer cf-token-secret");
  });

  it("routes a rejected record to manual even when it oddly carries a result (outer OR)", async () => {
    // Line 214 OUTER `||` -> `&&`: with `&&`, a failed write that still returned
    // a result object would be counted as applied. It must go to manual.
    const fetchMock = fetchFn(
      withZoneRead([], async () =>
        cfEnvelope(
          { id: "leaked-id" },
          { success: false, status: 400, errors: [{ code: 1004, message: "bad" }] },
        ),
      ),
    );
    vi.stubGlobal("fetch", fetchMock);
    const out = await new CloudflareAdapter().apply("example.com", [record], AUTH);
    expect(out.applied).toHaveLength(0);
    expect(out.manual).toHaveLength(1);
    expect(out.manual[0]!.note).toContain("1004");
  });

  it("uses the friendly note when a rejection carries an EMPTY errors array", async () => {
    // cfErrorText line 109: prevents `!errors || errors.length === 0` collapsing
    // and the fallback string being blanked. An empty errors[] must produce the
    // human sentence, not "".
    const fetchMock = fetchFn(
      withZoneRead([], async () =>
        cfEnvelope(null, { success: false, status: 400, errors: [] }),
      ),
    );
    vi.stubGlobal("fetch", fetchMock);
    const out = await new CloudflareAdapter().apply("example.com", [record], AUTH);
    expect(out.manual).toHaveLength(1);
    expect(out.manual[0]!.note).toBe("Cloudflare API rejected the record.");
  });
});

// ---------------------------------------------------------------------------
// readBack — the error paths were uncovered (lines 245, 249). Success paths
// live in cloudflare.test.ts.
// ---------------------------------------------------------------------------
describe("readBack error paths", () => {
  const record: DnsRecord = { type: "TXT", host: "@", value: "x", ttl: 300 };

  it("sends the Bearer header", async () => {
    // Prevents blanking readBack's Authorization header / headers object.
    const fetchMock = fetchFn(async () => cfEnvelope([]));
    vi.stubGlobal("fetch", fetchMock);
    await readBack("zone123", "cf-token-secret", record);
    expect(headersOf(fetchMock.mock.calls[0]![1]!).Authorization).toBe("Bearer cf-token-secret");
  });

  it("throws provider_auth_failed on 401 and 403", async () => {
    // Line 245 auth guard + equality.
    for (const status of [401, 403]) {
      vi.stubGlobal("fetch", fetchFn(async () => new Response("no", { status })));
      await expect(readBack("zone123", "tok", record)).rejects.toMatchObject({
        code: "provider_auth_failed",
      });
    }
  });

  it("throws provider_rejected when success is false", async () => {
    // Line 249 guard.
    vi.stubGlobal(
      "fetch",
      fetchFn(async () => cfEnvelope(null, { success: false, errors: [{ code: 9, message: "nope" }] })),
    );
    await expect(readBack("zone123", "tok", record)).rejects.toMatchObject({
      code: "provider_rejected",
    });
  });

  it("rejects a success:false body that still carries a result (outer OR)", async () => {
    // Line 249 OUTER `||` -> `&&`.
    vi.stubGlobal(
      "fetch",
      fetchFn(async () => cfEnvelope([{ id: "x" }], { success: false })),
    );
    await expect(readBack("zone123", "tok", record)).rejects.toMatchObject({
      code: "provider_rejected",
    });
  });

  it("NEGATIVE CONTROL: a clean success returns the result array", async () => {
    // If any guard mutant flipped to "always throw", this would fail.
    const rows = [{ id: "r1", type: "TXT", name: "example.com", content: "x", ttl: 300 }];
    vi.stubGlobal("fetch", fetchFn(async () => cfEnvelope(rows)));
    await expect(readBack("zone123", "tok", record)).resolves.toEqual(rows);
  });
});

// ---------------------------------------------------------------------------
// capabilities — the metadata mutants. (src lines 113-125)
// ---------------------------------------------------------------------------
describe("capabilities metadata", () => {
  it("capabilities() returns the full descriptor (block not emptied)", async () => {
    // Prevents the method body collapsing to {} (which returns undefined).
    expect(new CloudflareAdapter().capabilities()).toEqual(CLOUDFLARE_CAPABILITIES);
  });

  it("advertises the display name and the exact writable record types", () => {
    // Prevents blanking displayName and emptying / blanking the writesRecordTypes
    // array. The full list is load-bearing: it gates what the engine will send.
    expect(CLOUDFLARE_CAPABILITIES.displayName).toBe("Cloudflare");
    expect(CLOUDFLARE_CAPABILITIES.id).toBe("cloudflare");
    expect(CLOUDFLARE_CAPABILITIES.writesRecordTypes).toEqual([
      "A",
      "AAAA",
      "CNAME",
      "CAA",
      "MX",
      "TXT",
      "NS",
    ]);
  });

  it("NEGATIVE CONTROL: does not advertise a type it cannot write", () => {
    // Guards the assertion above from passing vacuously against an empty array.
    expect(CLOUDFLARE_CAPABILITIES.writesRecordTypes).not.toContain("SRV");
    expect(CLOUDFLARE_CAPABILITIES.writesRecordTypes.length).toBe(7);
  });
});
