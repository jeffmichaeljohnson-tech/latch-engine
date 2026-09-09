// The DohResolver is the one class in the engine that touches the network, so
// the unit suite injects a fake Resolver everywhere else and this class went
// untested. But its request shape is load-bearing: a DoH JSON endpoint answers
// nothing useful without the `application/dns-json` accept header, the `do=1`
// flag is the whole DNSSEC signal ./detect reads, and a non-ok HTTP status must
// raise rather than be parsed as an empty (and therefore NXDOMAIN-looking)
// answer. These pin the request it builds and the error path it takes, with a
// stubbed global fetch so no lookup leaves the machine.
import { describe, it, expect, afterEach } from "vitest";
import {
  DohResolver,
  DOH_ENDPOINTS,
  RR_TYPE,
  readTxt,
  type DnsResponse,
} from "../../src/net/resolver";

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

/** Capture the request DohResolver makes, and answer with a canned response. */
function stubFetch(response: Partial<Response> & { jsonBody?: unknown } = {}) {
  const calls: { url: string; init?: RequestInit }[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({ url: String(input), init });
    return {
      ok: response.ok ?? true,
      status: response.status ?? 200,
      json: async () => response.jsonBody ?? { Status: 0 },
    } as Response;
  }) as typeof fetch;
  return calls;
}

describe("DohResolver.query()", () => {
  it("puts the queried name and type in the URL and asks for dns-json", async () => {
    const calls = stubFetch();
    await new DohResolver().query("example.com", "A");
    const url = new URL(calls[0]!.url);
    expect(url.origin + url.pathname).toBe(DOH_ENDPOINTS.cloudflare);
    expect(url.searchParams.get("name")).toBe("example.com");
    expect(url.searchParams.get("type")).toBe("A");
    const headers = (calls[0]!.init!.headers ?? {}) as Record<string, string>;
    expect(headers.accept).toBe("application/dns-json");
  });

  it("sets the DNSSEC do-flag only when dnssec is requested", async () => {
    const withFlag = stubFetch();
    await new DohResolver().query("example.com", "DS", { dnssec: true });
    expect(new URL(withFlag[0]!.url).searchParams.get("do")).toBe("1");

    const withoutFlag = stubFetch();
    await new DohResolver().query("example.com", "DS");
    expect(new URL(withoutFlag[0]!.url).searchParams.has("do")).toBe(false);
  });

  it("a per-query endpoint overrides the resolver's primary", async () => {
    const calls = stubFetch();
    await new DohResolver().query("example.com", "A", {
      endpoint: DOH_ENDPOINTS.google,
    });
    const url = new URL(calls[0]!.url);
    expect(url.origin + url.pathname).toBe(DOH_ENDPOINTS.google);
  });

  it("honours a non-default primary passed to the constructor", async () => {
    const calls = stubFetch();
    await new DohResolver(DOH_ENDPOINTS.google).query("example.com", "A");
    const url = new URL(calls[0]!.url);
    expect(url.origin + url.pathname).toBe(DOH_ENDPOINTS.google);
  });

  it("returns the parsed JSON body on a 200", async () => {
    stubFetch({ jsonBody: { Status: 0, AD: true } });
    const resp = await new DohResolver().query("example.com", "A");
    expect(resp).toEqual({ Status: 0, AD: true });
  });

  it("throws — naming status, type and name — on a non-ok response", async () => {
    stubFetch({ ok: false, status: 502 });
    await expect(new DohResolver().query("bad.example", "TXT")).rejects.toThrow(
      /502.*TXT bad\.example/,
    );
  });
});

describe("readTxt()", () => {
  const resp: DnsResponse = {
    Status: 0,
    Answer: [
      { name: "example.com", type: 16, TTL: 300, data: '"v=spf1 -all"' },
      { name: "example.com", type: 5, TTL: 300, data: "cname.example." },
      { name: "example.com", type: 16, TTL: 300, data: '"a" "b"' },
    ],
  };

  it("returns only TXT answers, unquoted and chunk-joined", () => {
    expect(readTxt(resp)).toEqual(["v=spf1 -all", "ab"]);
  });

  it("is empty when there is no Answer section", () => {
    expect(readTxt({ Status: 3 })).toEqual([]);
  });
});

describe("RR_TYPE", () => {
  it("maps the numeric RR codes the resolver hands back to their names", () => {
    expect(RR_TYPE[1]).toBe("A");
    expect(RR_TYPE[16]).toBe("TXT");
    expect(RR_TYPE[257]).toBe("CAA");
    expect(RR_TYPE[48]).toBe("DNSKEY");
  });
});
