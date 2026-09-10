// Latch — Amazon Route 53 adapter: mutation-hardening tests.
//
// Companion to route53.test.ts. That file pins the happy path, the get-vanilla
// SigV4 vector, and one 403 case; this one closes the mutants that survived it —
// the auth reader's per-field guard and optional chaining, the zone-id
// normalizer's regex anchors, XML escaping, FQDN construction, TXT quoting,
// record grouping, the full ChangeBatch envelope, the request the adapter signs
// and sends (method, region, service, content type, session token), the HTTP
// status handling, the applied-record mapping, the error extractor, and the
// exported capability descriptor.
//
// Each test says WHICH defect it prevents, and each group carries a negative
// control so a mutant that always returns the positive answer cannot pass.
//
// No test performs a real network call: fetch is stubbed for every case. The
// non-exported helpers (readAuth, normalizeZoneId, toFqdn, toValue, route53Error)
// are exercised through the exported buildChangeBatchXml and Route53Adapter.apply
// and observed via the emitted XML and the intercepted fetch request. SigV4 is
// the REAL signer (its own mutants live in sigv4.mutants.test.ts); the adapter's
// signing wiring (method/region/service) is checked by re-deriving the signature
// independently and by inspecting the credential scope.

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  Route53Adapter,
  buildChangeBatchXml,
  ROUTE53_CAPABILITIES,
} from "../../src/providers/route53";
import { signRequest } from "../../src/providers/sigv4";
import { LatchError } from "../../src/types";
import type { DnsRecord } from "../../src/types";

const AUTH = {
  accessKeyId: "AKIAEXAMPLE",
  secretAccessKey: "secret-key",
  hostedZoneId: "/hostedzone/Z123ABC",
};

const OK_BODY = `<?xml version="1.0"?>
<ChangeResourceRecordSetsResponse><ChangeInfo><Id>/change/C1</Id><Status>PENDING</Status></ChangeInfo></ChangeResourceRecordSetsResponse>`;

type FetchImpl = (input: string | URL, init?: RequestInit) => Promise<Response>;

function fetchFn(impl: FetchImpl) {
  return vi.fn(impl);
}

/** Stub fetch to answer with a fixed status/body and return the spy. */
function stubFetch(body = OK_BODY, status = 200) {
  const m = fetchFn(async () => new Response(body, { status }));
  vi.stubGlobal("fetch", m);
  return m;
}

const A = (host: string, value = "1.2.3.4", ttl = 300): DnsRecord => ({
  type: "A",
  host,
  value,
  ttl,
});

afterEach(() => vi.unstubAllGlobals());

// ===========================================================================
// readAuth — the per-field credential guard, reached through apply(). (L38-59)
// ===========================================================================
describe("readAuth (via apply)", () => {
  it("throws a LatchError (not a raw TypeError) when auth is entirely absent", async () => {
    // Prevents dropping the optional chaining on auth?.["accessKeyId"] etc.:
    // without it, undefined auth throws "Cannot read properties of undefined"
    // instead of the typed provider_auth_failed error. fetch must not be reached.
    const fetchMock = stubFetch();
    const err = await new Route53Adapter()
      .apply("example.com", [A("@")], undefined)
      .then(() => null)
      .catch((e) => e);
    expect(err).toBeInstanceOf(LatchError);
    expect(err.code).toBe("provider_auth_failed");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  // Each row invalidates exactly ONE required field, isolating one operand of
  // the OR guard. Prevents any single `typeof ... !== "string"` check being
  // forced false, and any || being turned into && (which would only throw when
  // several fields fail at once). sessionToken is optional, so it is not tested
  // here.
  const missing: Array<[string, Record<string, unknown>]> = [
    ["accessKeyId", { secretAccessKey: "s", hostedZoneId: "Z" }],
    ["secretAccessKey", { accessKeyId: "a", hostedZoneId: "Z" }],
    ["hostedZoneId", { accessKeyId: "a", secretAccessKey: "s" }],
  ];
  for (const [field, auth] of missing) {
    it(`rejects provider_auth_failed when ${field} is missing (guard block not emptied)`, async () => {
      // Also catches emptying the throw block (L47) to {}: with no throw, apply
      // would proceed to sign/fetch with undefined creds instead of rejecting.
      const fetchMock = stubFetch();
      const err = await new Route53Adapter()
        .apply("example.com", [A("@")], auth as never)
        .catch((e) => e);
      expect(err).toBeInstanceOf(LatchError);
      expect(err.code).toBe("provider_auth_failed");
      expect(fetchMock).not.toHaveBeenCalled();
    });
  }

  it("carries the exact error code and a message naming what auth needs", async () => {
    // Prevents blanking the "provider_auth_failed" code (L49) or the human
    // message (L50) to "".
    const err = (await new Route53Adapter()
      .apply("example.com", [A("@")], {} as never)
      .catch((e) => e)) as LatchError;
    expect(err.code).toBe("provider_auth_failed");
    expect(err.message).toContain("accessKeyId");
    expect(err.message.length).toBeGreaterThan(0);
  });

  it("NEGATIVE CONTROL: fully-valid auth does not throw from readAuth", async () => {
    // If any guard mutant flipped to "always throw", this fails. Proves the
    // rejections above come from missing fields, not a broken accept path.
    stubFetch();
    const out = await new Route53Adapter().apply("example.com", [A("@")], AUTH);
    expect(out.applied).toHaveLength(1);
  });
});

// ===========================================================================
// normalizeZoneId — strip the "/hostedzone/" prefix. (L62-63)
// ===========================================================================
describe("normalizeZoneId (via the signed URL)", () => {
  async function urlFor(hostedZoneId: string): Promise<string> {
    const fetchMock = stubFetch();
    await new Route53Adapter().apply("example.com", [A("@")], {
      ...AUTH,
      hostedZoneId,
    });
    return String(fetchMock.mock.calls[0]![0]);
  }

  it("strips a leading /hostedzone/ prefix", async () => {
    // Baseline: the documented prefix form must be removed.
    expect(await urlFor("/hostedzone/Z123ABC")).toBe(
      "https://route53.amazonaws.com/2013-04-01/hostedzone/Z123ABC/rrset",
    );
  });

  it("strips the prefix even without a leading slash (the `/?` is optional)", async () => {
    // Prevents the regex /^\/?hostedzone\// -> /^\/hostedzone\// (dropping the
    // optional slash), which would fail to strip a slash-less "hostedzone/Z9".
    expect(await urlFor("hostedzone/Z9")).toContain("/hostedzone/Z9/rrset");
  });

  it("NEGATIVE CONTROL: only strips at the START, not mid-string (^ anchor)", async () => {
    // Prevents the regex /^\/?hostedzone\// -> /\/?hostedzone\// (dropping the ^
    // anchor): an id that merely CONTAINS "hostedzone/" must be left intact, not
    // have the middle spliced out.
    const url = await urlFor("Z1-hostedzone/-keep");
    expect(url).toContain("/hostedzone/Z1-hostedzone/-keep/rrset");
  });
});

// ===========================================================================
// xmlEscape — & < > escaping. (L66-72, esp. L68-70)
// ===========================================================================
describe("xmlEscape (via buildChangeBatchXml)", () => {
  it("escapes &, < and > in a record value", async () => {
    // Prevents each replacement target being blanked to "" (e.g. .replace(/&/g,
    // "") instead of "&amp;"), which would emit raw metacharacters and break the
    // XML.
    const xml = buildChangeBatchXml("example.com", [A("@", "a&b<c>d")]);
    expect(xml).toContain("a&amp;b&lt;c&gt;d");
    // NEGATIVE CONTROL: the raw, unescaped form must NOT survive.
    expect(xml).not.toContain("a&b<c>d");
  });
});

// ===========================================================================
// toFqdn — canonical host -> trailing-dot FQDN. (L74-81)
// ===========================================================================
describe("toFqdn (via buildChangeBatchXml Name)", () => {
  function nameOf(xml: string): string {
    return xml.match(/<Name>([^<]*)<\/Name>/)![1]!;
  }

  it("maps the apex forms (@, empty, bare domain) to the domain FQDN", async () => {
    // Prevents the apex `if` operands being forced false and the "" / "@"
    // comparison literals being swapped (e.g. to "Stryker was here!"): each apex
    // form must resolve to "example.com.", never ".example.com." or a doubled name.
    for (const host of ["@", "", "example.com"]) {
      expect(nameOf(buildChangeBatchXml("example.com", [A(host)]))).toBe("example.com.");
    }
  });

  it("qualifies a bare label with the domain and one trailing dot", async () => {
    // NEGATIVE CONTROL for the apex cases: a real label must be suffixed, not
    // folded to the apex. Also pins exactly one trailing dot.
    expect(nameOf(buildChangeBatchXml("example.com", [A("mail")]))).toBe("mail.example.com.");
  });

  it("leaves an already-qualified subdomain untouched (endsWith, not startsWith)", async () => {
    // Prevents the `host.endsWith(`.${domain}`)` branch being forced false and
    // endsWith -> startsWith: an FQDN under the domain must not be re-suffixed
    // into "sub.example.com.example.com.".
    expect(nameOf(buildChangeBatchXml("example.com", [A("sub.example.com")]))).toBe(
      "sub.example.com.",
    );
  });

  it("appends the trailing dot when the name lacks one (endsWith, not startsWith)", async () => {
    // Prevents `name.endsWith(".")` -> `name.startsWith(".")` on L80. A name that
    // begins with a dot (".x" -> ".x.example.com") starts with "." but does not
    // end with one, so the startsWith mutant would skip the required trailing dot.
    expect(nameOf(buildChangeBatchXml("example.com", [A(".x")]))).toBe(".x.example.com.");
  });
});

// ===========================================================================
// toValue — MX priority prefix and TXT quoting/escaping. (L88-98)
// ===========================================================================
describe("toValue (via buildChangeBatchXml)", () => {
  it("quotes and escapes an unquoted TXT value's backslashes and quotes", async () => {
    // Prevents the two escape replacements being blanked to "" (L94): a
    // backslash must double to \\ and an interior quote must become \" before
    // the whole value is wrapped in quotes (and XML-escaped to &quot;).
    const xml = buildChangeBatchXml("example.com", [
      { type: "TXT", host: "@", value: 'a\\b"c', ttl: 300 },
    ]);
    // Wrapped in &quot;...&quot;, backslash doubled, interior quote -> \&quot;
    expect(xml).toContain("&quot;a\\\\b\\&quot;c&quot;");
  });

  it("passes a pre-quoted TXT value through unchanged (startsWith, not endsWith)", async () => {
    // Prevents the `value.startsWith('"')` guard being forced false (a
    // pre-chunked value would be re-escaped) and startsWith -> endsWith (a value
    // that starts, but does not end, with a quote would be wrongly re-escaped).
    const xml = buildChangeBatchXml("example.com", [
      { type: "TXT", host: "@", value: '"already chunked', ttl: 300 },
    ]);
    // Pass-through: the lone leading quote is only XML-escaped, never doubled to
    // a backslash-quote.
    expect(xml).toContain("<Value>&quot;already chunked</Value>");
  });

  it("prefixes MX values with their priority", async () => {
    // Prevents the MX branch being disabled: the priority must lead the value.
    const xml = buildChangeBatchXml("example.com", [
      { type: "MX", host: "@", value: "mx.example.net", ttl: 300, priority: 15 },
    ]);
    expect(xml).toContain("<Value>15 mx.example.net</Value>");
  });
});

// ===========================================================================
// groupRecords — group by (name, type); TTL is the max of the group. (L108-123)
// ===========================================================================
describe("groupRecords (via buildChangeBatchXml)", () => {
  it("keeps distinct (name,type) pairs as separate record sets", async () => {
    // Prevents the group key template `${type}::${name}` being blanked to ``
    // (all records collapse into ONE set). Two different types must yield two sets.
    const xml = buildChangeBatchXml("example.com", [
      A("@", "1.2.3.4"),
      { type: "TXT", host: "@", value: "hello", ttl: 300 },
    ]);
    expect(xml.match(/<ResourceRecordSet>/g)).toHaveLength(2);
  });

  it("uses the MAX ttl across a merged group, not the min", async () => {
    // Prevents Math.max -> Math.min (L117): two A records at the same name+type
    // with ttls 300 and 600 must report TTL 600.
    const xml = buildChangeBatchXml("example.com", [A("@", "1.1.1.1", 300), A("@", "2.2.2.2", 600)]);
    expect(xml.match(/<ResourceRecordSet>/g)).toHaveLength(1);
    expect(xml).toContain("<TTL>600</TTL>");
    // NEGATIVE CONTROL: the min must NOT be the reported ttl.
    expect(xml).not.toContain("<TTL>300</TTL>");
  });
});

// ===========================================================================
// buildChangeBatchXml — the envelope structure and joins. (L126-150, L29)
// ===========================================================================
describe("buildChangeBatchXml envelope", () => {
  it("emits the XML declaration, the namespaced root, and its close tag", async () => {
    // Prevents blanking the declaration (L145), the root-open template with its
    // xmlns (L146), the XMLNS constant (L29), and the closing tag (L148).
    const xml = buildChangeBatchXml("example.com", [A("@")]);
    expect(xml.startsWith('<?xml version="1.0" encoding="UTF-8"?>')).toBe(true);
    expect(xml).toContain(
      '<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/">',
    );
    expect(xml).toContain("</ChangeResourceRecordSetsRequest>");
    expect(xml).toContain("</ResourceRecordSet></Change>");
  });

  it("joins multiple ResourceRecords with no separator text", async () => {
    // Prevents the inner .join("") -> "Stryker was here!" (L132): two values in
    // one set must sit directly adjacent, with no injected text between them.
    const xml = buildChangeBatchXml("example.com", [
      { type: "MX", host: "@", value: "mx1.net", ttl: 300, priority: 10 },
      { type: "MX", host: "@", value: "mx2.net", ttl: 300, priority: 20 },
    ]);
    expect(xml).toContain("</ResourceRecord><ResourceRecord>");
    expect(xml).not.toContain("Stryker");
  });

  it("joins multiple Changes with no separator text", async () => {
    // Prevents the outer .join("") -> "Stryker was here!" (L143): two distinct
    // change sets must be directly adjacent.
    const xml = buildChangeBatchXml("example.com", [
      A("a", "1.1.1.1"),
      A("b", "2.2.2.2"),
    ]);
    expect(xml).toContain("</Change><Change>");
    expect(xml).not.toContain("Stryker");
  });
});

// ===========================================================================
// apply — the signed request the adapter sends. (L167-196, L27-28)
// ===========================================================================
describe("apply request wiring", () => {
  it("signs with method POST, region us-east-1 and service route53 (re-derived)", async () => {
    // Prevents method:"POST" -> "" (L181) and REGION/SERVICE -> "" (L27-28).
    // The adapter uses a live timestamp, so the signature is re-derived here from
    // the intercepted request using the CORRECT method/region/service; a mutated
    // adapter would have produced a signature that no longer matches.
    const fetchMock = stubFetch();
    await new Route53Adapter().apply("example.com", [A("@")], AUTH);

    const [url, init] = fetchMock.mock.calls[0]!;
    const headers = init!.headers as Record<string, string>;
    const body = init!.body as string;

    const expected = await signRequest({
      method: "POST",
      url: String(url),
      region: "us-east-1",
      service: "route53",
      accessKeyId: AUTH.accessKeyId,
      secretAccessKey: AUTH.secretAccessKey,
      body,
      amzDate: headers["x-amz-date"],
    });
    expect(headers.authorization).toBe(expected.authorization);
    // Direct read of the scope so REGION/SERVICE blanking is legible on its own.
    expect(headers.authorization).toContain("/us-east-1/route53/aws4_request");
  });

  it("sends Content-Type: application/xml on the POST", async () => {
    // Prevents the "application/xml" content-type value being blanked to "" (L193).
    const fetchMock = stubFetch();
    await new Route53Adapter().apply("example.com", [A("@")], AUTH);
    const init = fetchMock.mock.calls[0]![1]!;
    expect(init.method).toBe("POST");
    expect((init.headers as Record<string, string>)["Content-Type"]).toBe("application/xml");
  });

  it("includes the session token as a signed header when supplied", async () => {
    // Prevents the sessionToken spread in apply (L187) being emptied/inverted and
    // the readAuth sessionToken key (L41) being blanked: a supplied token must be
    // read AND signed into the request as x-amz-security-token.
    const fetchMock = stubFetch();
    await new Route53Adapter().apply("example.com", [A("@")], {
      ...AUTH,
      sessionToken: "sts-token-123",
    });
    const headers = fetchMock.mock.calls[0]![1]!.headers as Record<string, string>;
    expect(headers["x-amz-security-token"]).toBe("sts-token-123");
  });

  it("NEGATIVE CONTROL: no session token means no x-amz-security-token header", async () => {
    // Guards the positive case above from passing against an adapter that always
    // attaches the token header.
    const fetchMock = stubFetch();
    await new Route53Adapter().apply("example.com", [A("@")], AUTH);
    const headers = fetchMock.mock.calls[0]![1]!.headers as Record<string, string>;
    expect(headers["x-amz-security-token"]).toBeUndefined();
  });
});

// ===========================================================================
// apply — the empty-records short-circuit. (L173)
// ===========================================================================
describe("apply empty-records short-circuit", () => {
  it("returns an empty result WITHOUT calling fetch when there are no records", async () => {
    // Prevents `records.length === 0` -> false (L173 conditional), which would
    // sign and POST an empty batch. Also pins the returned object shape against
    // the {} / ["Stryker was here"] literal mutants.
    const fetchMock = stubFetch();
    const out = await new Route53Adapter().apply("example.com", [], AUTH);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(out).toEqual({ applied: [], manual: [] });
  });

  it("NEGATIVE CONTROL: a non-empty batch DOES call fetch", async () => {
    // Proves the short-circuit above is conditional, not unconditional.
    const fetchMock = stubFetch();
    await new Route53Adapter().apply("example.com", [A("@")], AUTH);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

// ===========================================================================
// apply — HTTP status handling and the applied mapping. (L196-208)
// ===========================================================================
describe("apply response handling", () => {
  it("maps 401 and 403 to provider_auth_failed (both operands of the ||)", async () => {
    // Prevents the 401||403 condition being forced false (L198) and either status
    // operand being individually disabled. Both are exercised.
    for (const status of [401, 403]) {
      stubFetch("<ErrorResponse><Error><Code>AccessDenied</Code><Message>no</Message></Error></ErrorResponse>", status);
      await expect(
        new Route53Adapter().apply("example.com", [A("@")], AUTH),
      ).rejects.toMatchObject({ code: "provider_auth_failed" });
    }
  });

  it("maps a non-auth error status to provider_rejected", async () => {
    // Prevents `!res.ok` -> false (L201) and blanking the provider_rejected
    // throw block/code (L201-202). A 500 must reject as provider_rejected.
    stubFetch("<ErrorResponse><Error><Code>InternalError</Code><Message>boom</Message></Error></ErrorResponse>", 500);
    await expect(
      new Route53Adapter().apply("example.com", [A("@")], AUTH),
    ).rejects.toMatchObject({ code: "provider_rejected" });
  });

  it("returns the input records as applied on success (full field copy)", async () => {
    // Prevents records.map((r) => ({ ...r })) collapsing to () => undefined or
    // ({}) -> {} (L206): the applied list must echo the real record, not
    // undefined or an empty object.
    stubFetch();
    const rec = A("www", "9.9.9.9", 120);
    const out = await new Route53Adapter().apply("example.com", [rec], AUTH);
    expect(out.manual).toEqual([]);
    expect(out.applied).toEqual([rec]);
  });
});

// ===========================================================================
// route53Error — parse <Code>/<Message> from the error XML. (L211-215)
// ===========================================================================
describe("route53Error (via apply rejection message)", () => {
  async function messageFor(body: string, status = 500): Promise<string> {
    stubFetch(body, status);
    const err = (await new Route53Adapter()
      .apply("example.com", [A("@")], AUTH)
      .catch((e) => e)) as LatchError;
    return err.message;
  }

  it("combines the parsed Code and Message verbatim", async () => {
    // Prevents: the capture groups being narrowed ([^<]* -> [^<] would give one
    // char; -> [<]* would capture nothing), `code ?? "Error"` -> `code && "Error"`
    // (drops the real code) and `message ?? default` -> `message && default`
    // (drops the real message), and the whole template being blanked to ``.
    const msg = await messageFor(
      "<Error><Code>AccessDenied</Code><Message>You are not authorized</Message></Error>",
    );
    expect(msg).toBe("AccessDenied: You are not authorized");
  });

  it("falls back to the default message when only a Code is present (|| not &&)", async () => {
    // Prevents `if (code || message)` -> `if (code && message)`: a Code with no
    // Message must still surface, using the default message tail.
    const msg = await messageFor("<Error><Code>Throttling</Code></Error>");
    expect(msg).toBe("Throttling: Route 53 rejected the change.");
  });

  it("uses ONLY the generic sentence when neither Code nor Message is present", async () => {
    // Prevents `if (code || message)` -> forced true (which would prepend
    // "Error: ") and the generic fallback (L215) being blanked to "". Also proves
    // the optional chaining `?.[1]` survives a no-match (a non-optional access
    // would throw a TypeError on null).
    const msg = await messageFor("plain text, no xml tags here");
    expect(msg).toBe("Route 53 rejected the change.");
  });
});

// ===========================================================================
// ROUTE53_CAPABILITIES — the exported descriptor. (L152-165)
// ===========================================================================
describe("ROUTE53_CAPABILITIES", () => {
  it("advertises the real identity, automation flag, apex support and record set", () => {
    // Prevents: displayName -> "" (L154), automated -> false (L155),
    // supportsApex -> false (L159), and writesRecordTypes emptied or any element
    // blanked (L157).
    expect(ROUTE53_CAPABILITIES.id).toBe("route53");
    expect(ROUTE53_CAPABILITIES.displayName).toBe("Amazon Route 53");
    expect(ROUTE53_CAPABILITIES.automated).toBe(true);
    expect(ROUTE53_CAPABILITIES.supportsApex).toBe(true);
    expect(ROUTE53_CAPABILITIES.writesRecordTypes).toEqual([
      "A",
      "AAAA",
      "CNAME",
      "CAA",
      "MX",
      "TXT",
      "NS",
    ]);
  });

  it("NEGATIVE CONTROL + capabilities() returns that same descriptor, not undefined", () => {
    // Prevents the capabilities() method body being emptied to {} (returns
    // undefined), and guards the array assertion above against passing vacuously.
    expect(new Route53Adapter().capabilities()).toEqual(ROUTE53_CAPABILITIES);
    expect(ROUTE53_CAPABILITIES.writesRecordTypes).not.toContain("SRV");
    expect(ROUTE53_CAPABILITIES.writesRecordTypes.length).toBe(7);
  });
});
