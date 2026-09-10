// Latch — AWS SigV4 signer: mutation-hardening tests.
//
// Companion to the SigV4 known-answer cases in route53.test.ts. That file pins
// the published get-vanilla vector and the header-whitespace equivalence; this
// one closes the mutants that survived them — the RFC-3986 encoder, the URI
// path canonicalizer, the query-string canonicalizer (early-return guard and
// the key/value sort), the body default, the header-value normalization, the
// x-amz-date default, and the session-token header.
//
// PROVENANCE, stated per the task rules:
//   * ORACLE  — a value AWS publishes. The only published signature used here is
//     the aws-sig-v4-test-suite "get-vanilla" case (access key AKIDEXAMPLE,
//     signature 5fa00fa3...). Re-running this implementation reproduces it
//     exactly, which is what makes it an oracle rather than a pin: it can
//     discover that the implementation is wrong.
//   * RULE    — a documented SigV4 property expressed as an equality/inequality
//     between two signatures (order-independence of the query, significance of
//     a space in a header value, undefined-body === empty-body, a signed header
//     participating). These need no external vector: the relationship itself is
//     the specification, and it can still fail.
//   * PIN     — a signature this implementation currently emits for a crafted
//     input, obtained by running the real code. A pin locks the exact bytes of
//     the encoder / path canonicalizer / value-tiebreak against mutation. It is
//     labelled because a pin CANNOT discover that the current output is wrong;
//     it only detects a CHANGE from it. Each pin sits beside a RULE or the
//     ORACLE that independently argues the current output is the correct one.
//
// No test performs a real network call — signRequest is pure (Web Crypto only).

import { describe, expect, it } from "vitest";
import { signRequest, type SigV4Input } from "../../src/providers/sigv4";

// The published vector's fixed inputs, reused so every crafted case shares one
// deterministic (key, date, region, service) context.
const BASE: SigV4Input = {
  method: "GET",
  url: "https://example.amazonaws.com/",
  region: "us-east-1",
  service: "service",
  accessKeyId: "AKIDEXAMPLE",
  secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
  amzDate: "20150830T123600Z",
  headers: { "x-amz-date": "20150830T123600Z" },
  body: "",
};

/** Sign BASE with `url` (and optional overrides) and return the hex signature. */
async function sig(overrides: Partial<SigV4Input>): Promise<string> {
  return (await signRequest({ ...BASE, ...overrides })).signature;
}

// ---------------------------------------------------------------------------
// ORACLE anchor — the whole pipeline computes a real AWS signature.
// aws-sig-v4-test-suite / get-vanilla. If any load-bearing canonicalization
// step is broken, this documented value stops reproducing.
// ---------------------------------------------------------------------------
describe("get-vanilla published vector (ORACLE)", () => {
  it("reproduces the AWS-documented signature and Authorization", async () => {
    const r = await signRequest(BASE);
    expect(r.signedHeaders).toBe("host;x-amz-date");
    // ORACLE: published by AWS in the aws-sig-v4-test-suite (get-vanilla).
    expect(r.signature).toBe(
      "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
    );
    expect(r.authorization).toContain(
      "Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request",
    );
  });
});

// ---------------------------------------------------------------------------
// body default — const body = input.body ?? "" (L113)
// ---------------------------------------------------------------------------
describe("body default", () => {
  it("RULE: an absent body signs identically to an empty-string body", async () => {
    // Prevents `?? ""` -> `?? "Stryker was here!"` (an absent body would hash a
    // marker string) and `input.body ?? ""` -> `input.body && ""` (an absent
    // body becomes `undefined`, which hashes the literal "undefined"). Under
    // either, sign(absent) diverges from sign("").
    const absent = await sig({ body: undefined });
    const empty = await sig({ body: "" });
    expect(absent).toBe(empty);
  });

  it("RULE + NEGATIVE CONTROL: a real body changes the signature", async () => {
    // The body genuinely participates, so the equality above is not vacuous.
    // Also catches `input.body && ""`: with it, a real body collapses to "" and
    // would sign the same as the empty body.
    const withBody = await sig({ body: "a-real-payload" });
    const empty = await sig({ body: "" });
    expect(withBody).not.toBe(empty);
  });
});

// ---------------------------------------------------------------------------
// header value normalization — v.trim().replace(/\s+/g, " ") (L122)
// ---------------------------------------------------------------------------
describe("header value normalization", () => {
  it("RULE: internal whitespace is collapsed to ONE space, not removed", async () => {
    // Prevents the replacement string " " -> "" (collapse to nothing). A single
    // interior space is significant: "a b" and "ab" are different header values
    // and must sign differently. The removal mutant would fold both to "ab".
    const spaced = await sig({ headers: { "x-amz-date": BASE.amzDate!, "my-header1": "a b" } });
    const joined = await sig({ headers: { "x-amz-date": BASE.amzDate!, "my-header1": "ab" } });
    expect(spaced).not.toBe(joined);
  });

  it("RULE: runs of whitespace collapse so padded == single-spaced (control for the above)", async () => {
    // The other direction, so the test above cannot be satisfied by a signer
    // that ignores the header entirely: "a   b" (multi-space) must sign the same
    // as "a b" (single space).
    const padded = await sig({ headers: { "x-amz-date": BASE.amzDate!, "my-header1": "a   b" } });
    const single = await sig({ headers: { "x-amz-date": BASE.amzDate!, "my-header1": "a b" } });
    expect(padded).toBe(single);
  });
});

// ---------------------------------------------------------------------------
// x-amz-date default — if (!headerMap.has("x-amz-date")) set it (L125)
// ---------------------------------------------------------------------------
describe("x-amz-date header default", () => {
  it("does NOT overwrite a caller-supplied x-amz-date header", async () => {
    // Prevents the guard being forced true and the "x-amz-date" literal being
    // blanked to "" (has("") is always false, so both make the branch fire
    // unconditionally and clobber the caller's header with the amzDate param).
    const r = await signRequest({
      ...BASE,
      headers: { "x-amz-date": "20200102T030405Z" },
      amzDate: "20150830T123600Z",
    });
    expect(r.headers["x-amz-date"]).toBe("20200102T030405Z");
  });

  it("NEGATIVE CONTROL: when the caller omits it, the amzDate default is used", async () => {
    // Proves the assertion above is about NOT clobbering, not about the field
    // being absent: with no header supplied, the default must appear.
    const r = await signRequest({
      ...BASE,
      headers: {},
      amzDate: "20150830T123600Z",
    });
    expect(r.headers["x-amz-date"]).toBe("20150830T123600Z");
  });
});

// ---------------------------------------------------------------------------
// session token header — if (input.sessionToken) set x-amz-security-token (L126)
// ---------------------------------------------------------------------------
describe("session token header", () => {
  it("signs x-amz-security-token into the request when a session token is given", async () => {
    // Prevents the guard being forced false (token never set) and the header
    // name "x-amz-security-token" being blanked to "" (the token would be filed
    // under an empty header name). Both the signed-headers list and the emitted
    // header set must carry the real name.
    const r = await signRequest({ ...BASE, sessionToken: "FQoGZXIvYXdzE-session" });
    expect(r.signedHeaders.split(";")).toContain("x-amz-security-token");
    expect(r.headers["x-amz-security-token"]).toBe("FQoGZXIvYXdzE-session");
  });

  it("NEGATIVE CONTROL: with no session token, the header is absent", async () => {
    // Guards the positive case from passing against a signer that always adds
    // the header.
    const r = await signRequest({ ...BASE, sessionToken: undefined });
    expect(r.signedHeaders.split(";")).not.toContain("x-amz-security-token");
    expect(r.headers["x-amz-security-token"]).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// canonical query string — early-return guard + key/value sort (L61-68)
// ---------------------------------------------------------------------------
describe("canonical query string", () => {
  it("RULE: the query participates in the signature", async () => {
    // Prevents canonicalQueryString short-circuiting to "" (block emptied,
    // guard forced true, `search === "?"` -> `search !== "?"`, `!search` ->
    // `search`). Any of those drops the query, so a request WITH a query would
    // sign identically to one without.
    const withQuery = await sig({ url: "https://example.amazonaws.com/?A=1&B=2" });
    const noQuery = await sig({ url: "https://example.amazonaws.com/" });
    expect(withQuery).not.toBe(noQuery);
  });

  it("RULE + NEGATIVE CONTROL: a different query value signs differently", async () => {
    // The query's CONTENT matters, so the inequality above is not satisfied by a
    // signer that appends a constant. Also fails any mutant that always emits "".
    const a = await sig({ url: "https://example.amazonaws.com/?A=1&B=2" });
    const b = await sig({ url: "https://example.amazonaws.com/?A=9&B=2" });
    expect(a).not.toBe(b);
  });

  it("RULE: params are sorted by key, so input order does not change the signature", async () => {
    // Prevents the sort being removed (`pairs.sort(...)` -> `pairs`, or the
    // comparator -> `() => undefined`) and the key comparator being reversed
    // (`-1` -> `+1` on the a[0] branch): each makes canonicalization
    // order-dependent, so a reordered query would sign differently.
    const forward = await sig({ url: "https://example.amazonaws.com/?A=1&B=2" });
    const reversed = await sig({ url: "https://example.amazonaws.com/?B=2&A=1" });
    expect(forward).toBe(reversed);
  });

  it("RULE: params with the SAME key are ordered by value, independent of input order", async () => {
    // Prevents the a[0] equality being loosened (`a[0] < b[0]` -> `a[0] <= b[0]`
    // / `>= b[0]`): those short-circuit the equal-key branch and skip the value
    // tiebreak, so two orderings of the same key would sign differently.
    const forward = await sig({ url: "https://example.amazonaws.com/?A=1&A=2" });
    const reversed = await sig({ url: "https://example.amazonaws.com/?A=2&A=1" });
    expect(forward).toBe(reversed);
  });

  it("PIN: the exact value-tiebreak ordering of a same-key query", async () => {
    // The equal-key value tiebreak can be REVERSED consistently (`a[1] < b[1]`
    // -> `a[1] >= b[1]`, or the `-1` on that branch -> `+1`). A reversal is
    // order-independent, so the RULE above cannot see it; this pin does, because
    // the reversed canonical string ("A=2&A=1") hashes to a different signature.
    // PIN: emitted by the current implementation for "?A=1&A=2"; the RULE above
    // argues A=1 must precede A=2, so this pin locks the correct ordering.
    const s = await sig({ url: "https://example.amazonaws.com/?A=1&A=2" });
    expect(s).toBe("373d18f636e172cf9ec1d08c53dde96554ef62f394eca70dd22fa11d5d4d1345");
  });

  it("PIN: RFC-3986 percent-encoding of reserved query characters", async () => {
    // encodeRfc3986 (L45-50) must render "*" as %2A and "!" as %21 (uppercase
    // hex). Kills: the regex /[!'()*]/ -> /[^!'()*]/ (encodes everything else
    // instead), the "%" literal -> "" ("2A" not "%2A"), toUpperCase ->
    // toLowerCase ("%2a"), the callback -> () => undefined ("undefined"), and the
    // function body -> {} (returns undefined). Each changes the encoded query and
    // thus the signature.
    // PIN: emitted for "?k=a*b!c" (value "a*b!c" -> "k=a%2Ab%21c"). The encoder
    // is a standard RFC-3986 encoder and the get-vanilla ORACLE proves the
    // surrounding pipeline, so this pin locks a form independently argued correct.
    const s = await sig({ url: "https://example.amazonaws.com/?k=a*b!c" });
    expect(s).toBe("144e935c3c5675970545921bdb3eafe2a5da491f8e52dd2d088e2892247cdc6a");
  });
});

// ---------------------------------------------------------------------------
// canonical URI path — encodeCanonicalUri (L52-59)
// ---------------------------------------------------------------------------
describe("canonical URI path", () => {
  it("RULE: the path participates — two different paths sign differently", async () => {
    // Prevents the "return '/'" short-circuit firing for real paths: the guard
    // forced true, or `path === ""` -> `path !== ""`, or `path === "/"` ->
    // `path !== "/"` (each returns "/" for any non-root path, collapsing all
    // paths to the same canonical value).
    const a = await sig({ url: "https://example.amazonaws.com/aaa" });
    const b = await sig({ url: "https://example.amazonaws.com/bbb" });
    expect(a).not.toBe(b);
  });

  it("RULE + NEGATIVE CONTROL: the root path still signs like get-vanilla", async () => {
    // "/" must canonicalize to "/", so the path handling above did not break the
    // documented root case. (This is the get-vanilla path.)
    const root = await sig({ url: "https://example.amazonaws.com/" });
    expect(root).toBe(
      "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
    );
  });

  it("PIN: exact encoding of a multi-segment path", async () => {
    // encodeCanonicalUri splits on "/", encodes each segment, and rejoins on
    // "/". Kills: .split("/") -> .split("") (per-character), the segment map ->
    // () => undefined ("undefined" segments), and .join("/") -> .join("")
    // ("foobar" instead of "/foo/bar"). Each changes the canonical path.
    // PIN: emitted for "/foo/bar" (a plain path with no reserved characters,
    // whose correct canonical form is itself, "/foo/bar").
    const s = await sig({ url: "https://example.amazonaws.com/foo/bar" });
    expect(s).toBe("6200de478e11b3c0ba4940fbbcacbc998521cf017165e77d5494b164768b3a5c");
  });
});
