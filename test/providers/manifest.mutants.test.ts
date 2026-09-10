// Latch — declarative manifest adapter: mutation-hardening tests.
//
// Companion to manifest.test.ts. That file pins the happy paths (a trusted
// apply, the safety gate, a well-formed validate, one readExisting map, and the
// DELETE-is-unreachable proof). This one closes the mutants that survived it:
//   - the placeholder/text substitution helpers (toFqdn, toHost, recordValues
//     priority, substitute auth + unknown-token fallback, joinUrl, getByPath),
//   - renderBody's array / object / primitive / null branches and the
//     undefined-drop filter,
//   - the Content-Type defaulting and the render-time method default,
//   - the whole of validateManifest (every required-field guard, the method
//     allowlists, the header validation, the placeholder rules, the record-type
//     and auth-kind sets), and
//   - readExisting's request shape, auth/rejection paths, non-array tolerance,
//     the default record map, and registerManifestAdapter's validate-then-register.
//
// Every test says WHICH defect it prevents, and each group carries a negative
// control so a helper that always returns the positive answer cannot pass.
//
// No test performs a real network call: fetch is supplied through the adapter's
// `fetch` option, and the global fetch is stubbed to throw so an accidental real
// call is loud rather than silent. registerAdapter is module-mocked so the
// registration test cannot leak an adapter into the shared registry other test
// files read.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Mock the registry so registerManifestAdapter's registration is observable and
// cannot pollute the process-wide adapter map that registry.test.ts / connect
// tests share. Isolated to this test module (vitest mocks are per-file).
vi.mock("../../src/providers/registry", () => ({
  registerAdapter: vi.fn(),
  getAdapter: vi.fn(),
  listAdapters: vi.fn(() => []),
}));

import {
  validateManifest,
  manifestAdapter,
  registerManifestAdapter,
  type AdapterManifest,
  type ManifestAdapter,
} from "../../src/providers/manifest";
import { registerAdapter } from "../../src/providers/registry";
import { LatchError } from "../../src/types";
import type { DnsRecord, DnsRecordType } from "../../src/types";

// A Cloudflare-shaped provider described purely as DATA (same shape as the
// happy-path test). Trust is a CALLER option, never a manifest field.
const VALID: AdapterManifest = {
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

const AUTH = { zoneId: "zone-42", token: "acme-secret" };
const A_REC: DnsRecord = { type: "A", host: "@", value: "1.2.3.4", ttl: 300 };

/** A fresh deep copy so a mutation in one test cannot bleed into another. */
function base(): AdapterManifest {
  return structuredClone(VALID);
}

/** Loosely-typed view for assigning intentionally-invalid field values. */
function loose(o: unknown): Record<string, unknown> {
  return o as Record<string, unknown>;
}

function fetchFn(impl: (input: string | URL, init?: RequestInit) => Promise<Response>) {
  return vi.fn(impl);
}

function okJson(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/** Synchronously render the one request a manifest would build for `record`. */
function reqOf(manifest: AdapterManifest, record: DnsRecord = A_REC, auth = AUTH) {
  return manifestAdapter(manifest).dryRun("example.com", [record], auth)[0]!;
}

/** Parse the rendered JSON body a manifest would send for `record`. */
function bodyOf(manifest: AdapterManifest, record: DnsRecord = A_REC) {
  return JSON.parse(reqOf(manifest, record).body) as Record<string, unknown>;
}

/** Assert a validate result failed AND names the expected fragment. */
function expectFail(res: ReturnType<typeof validateManifest>, fragment: string): void {
  expect(res.ok).toBe(false);
  if (!res.ok) expect(res.errors.some((e) => e.includes(fragment))).toBe(true);
}

beforeEach(() => {
  // Any code path that reaches the *global* fetch is a defect here — every real
  // fetch must arrive through the adapter's `fetch` option.
  vi.stubGlobal(
    "fetch",
    vi.fn(() => {
      throw new Error("a real global fetch was made; tests must inject fetch via options");
    }),
  );
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  vi.clearAllMocks();
});

// ===========================================================================
// toFqdn — via the rendered body `name: "{fqdn}"` field.
// ===========================================================================
describe("toFqdn (via body.name)", () => {
  const nameFor = (host: string, type: DnsRecordType = "A") =>
    bodyOf(base(), { type, host, value: "1.2.3.4", ttl: 300 }).name;

  it('maps the "@" apex to the bare domain', () => {
    // Prevents the apex branch being forced false and the "@" literal being
    // swapped: "@" must become "example.com", not "@.example.com".
    expect(nameFor("@")).toBe("example.com");
  });

  it('maps an empty host "" to the bare domain', () => {
    // The other operand of the apex OR: "" must also resolve to the apex.
    expect(nameFor("")).toBe("example.com");
  });

  it("leaves a host already equal to the domain untouched (no doubling)", () => {
    // Prevents `||` -> `&&` and the `host === domain` term flipping to false:
    // the bare domain must not become "example.com.example.com".
    expect(nameFor("example.com")).toBe("example.com");
  });

  it("leaves an already-qualified subdomain untouched (endsWith, not startsWith)", () => {
    // Prevents endsWith -> startsWith on the FQDN check: an FQDN would otherwise
    // be re-suffixed into "mail.example.com.example.com".
    expect(nameFor("mail.example.com")).toBe("mail.example.com");
  });

  it("NEGATIVE CONTROL: a bare label IS qualified with the domain", () => {
    // If toFqdn always returned its input, every case above would pass vacuously.
    expect(nameFor("mail")).toBe("mail.example.com");
  });
});

// ===========================================================================
// recordValues — the priority string, observed by embedding {priority} in text.
// ===========================================================================
describe("recordValues priority string (via a text-embedded {priority})", () => {
  function priText(record: DnsRecord): string {
    const m = base();
    m.create.bodyTemplate = { p: "p<{priority}>" };
    return bodyOf(m, record).p as string;
  }

  it("an MX record's numeric priority is stringified into the text", () => {
    // Prevents the ternary being forced to always-"" (which would erase a real 5).
    expect(priText({ type: "MX", host: "@", value: "mx.acme.test", ttl: 300, priority: 5 })).toBe("p<5>");
  });

  it("NEGATIVE CONTROL: a record with no priority substitutes the empty string, not \"undefined\"", () => {
    // Prevents `== null` -> `!= null`, the ternary being forced to always-String
    // (yielding "undefined"), and the "" literal being swapped: a priority-less
    // record must render "p<>" not "p<undefined>" / "p<Stryker...>".
    expect(priText({ type: "A", host: "@", value: "1.2.3.4", ttl: 300 })).toBe("p<>");
  });
});

// ===========================================================================
// substitute — auth resolution, its optional chaining, and the unknown-token
// fallback. Exercised through dryRun (no fetch).
// ===========================================================================
describe("substitute (auth + unknown-token fallback)", () => {
  it("a missing auth field raises a typed LatchError, not a raw TypeError", () => {
    // Prevents `auth?.[key]` being weakened to `auth[key]`: with undefined auth
    // that throws "Cannot read properties of undefined" instead of the typed
    // provider_auth_failed the caller is contracted to catch. Also prevents the
    // error message being blanked (it must name the field it needs).
    const adapter = manifestAdapter(base());
    let err: unknown;
    try {
      adapter.dryRun("example.com", [A_REC]); // no auth arg
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(LatchError);
    expect((err as LatchError).code).toBe("provider_auth_failed");
    expect((err as Error).message).toContain("token");
  });

  it("NEGATIVE CONTROL: with auth present the same manifest renders without throwing", () => {
    // If the auth check were forced to always-throw, this would fail.
    expect(manifestAdapter(base()).dryRun("example.com", [A_REC], AUTH)).toHaveLength(1);
  });

  it("an unknown (non-auth) placeholder substitutes to empty text, not a marker", () => {
    // Prevents `values[token] ?? ""` -> `... ?? "Stryker was here!"`: the runtime
    // fail-safe for an unrecognised placeholder is an empty string. Built through
    // manifestAdapter (which does not validate) so the token reaches substitute.
    const m = base();
    m.create.path = "/x/{unknownXYZ}/y";
    expect(reqOf(m).url).toBe("https://api.acme.test/v1/x//y");
  });
});

// ===========================================================================
// joinUrl — trailing/leading slash normalization.
// ===========================================================================
describe("joinUrl (slash normalization)", () => {
  it("joins baseUrl and path with exactly one slash (default shape)", () => {
    // Prevents the whole template being replaced with a fixed marker string.
    expect(reqOf(base()).url).toBe("https://api.acme.test/v1/zones/zone-42/records");
  });

  it("strips ONLY a trailing baseUrl slash and ONLY a leading path slash", () => {
    // Prevents either replace regex (`/\/$/`, `/^\//`) being widened to `/\//`,
    // which removes the FIRST slash anywhere and corrupts the scheme or an
    // interior path segment. baseUrl has a trailing slash; path has an interior
    // slash and no leading one, so a first-slash-anywhere removal is observable.
    const m = base();
    m.baseUrl = "https://api.acme.test/v1/";
    m.create.path = "zones/inner/x";
    expect(reqOf(m).url).toBe("https://api.acme.test/v1/zones/inner/x");
  });
});

// ===========================================================================
// renderBody — arrays, objects, primitives, null, and the undefined-drop filter.
// ===========================================================================
describe("renderBody (arrays / primitives / null)", () => {
  it("renders a template array AS an array of substituted values", () => {
    // Prevents the `Array.isArray` branch being emptied / forced false, which
    // would let an array fall through to object handling and emit {"0":...}.
    const m = base();
    m.create.bodyTemplate = { arr: ["{type}", "{value}"] };
    const body = bodyOf(m);
    expect(Array.isArray(body.arr)).toBe(true);
    expect(body.arr).toEqual(["A", "1.2.3.4"]);
  });

  it("drops undefined array elements but keeps real ones (the .filter)", () => {
    // Prevents the trailing `.filter(v => v !== undefined)` being removed, the
    // predicate being forced true/false, its callback becoming () => undefined,
    // the map callback becoming () => undefined, and `!==` becoming `===`. For a
    // priority-less A record `{priority}` renders undefined and must vanish,
    // while `{type}` must survive.
    const m = base();
    m.create.bodyTemplate = { arr: ["{type}", "{priority}"] };
    expect(bodyOf(m, { type: "A", host: "@", value: "1.2.3.4", ttl: 300 }).arr).toEqual(["A"]);
  });

  it("NEGATIVE CONTROL: a real numeric priority in an array is KEPT (filter is not blanket)", () => {
    // Guards the drop-test above from passing against a filter that removes
    // everything: an MX priority of 7 must remain, as a number.
    const m = base();
    m.create.bodyTemplate = { arr: ["{type}", "{priority}"] };
    expect(bodyOf(m, { type: "MX", host: "@", value: "mx.acme.test", ttl: 300, priority: 7 }).arr).toEqual([
      "MX",
      7,
    ]);
  });

  it("passes primitive and null leaves through unchanged", () => {
    // Prevents the object-branch guard `t !== null && typeof t === "object"`
    // being forced true (a number would become {} and null would throw) and the
    // `&&` becoming `||` (null -> Object.entries(null) throws).
    const m = base();
    m.create.bodyTemplate = { s: "{type}", n: 42, b: true, z: null };
    expect(bodyOf(m)).toEqual({ s: "A", n: 42, b: true, z: null });
  });
});

// ===========================================================================
// renderRequest — Content-Type defaulting and the render-time method default.
// ===========================================================================
describe("renderRequest headers + method", () => {
  it("adds Content-Type: application/json when the manifest sets none", () => {
    expect(reqOf(base()).headers["Content-Type"]).toBe("application/json");
  });

  it("substitutes an auth placeholder into a header value", () => {
    // Prevents renderHeaders dropping the substitution.
    expect(reqOf(base()).headers.Authorization).toBe("Bearer acme-secret");
  });

  it("does NOT overwrite an explicit Content-Type", () => {
    // Prevents the guard being forced true and `&&` -> `||`: a manifest-supplied
    // Content-Type must survive, not be replaced with application/json.
    const m = base();
    m.create.headers = { Authorization: "Bearer {auth:token}", "Content-Type": "text/plain" };
    expect(reqOf(m).headers["Content-Type"]).toBe("text/plain");
  });

  it("treats a lowercase content-type as already-present (no capital duplicate added)", () => {
    // Prevents the `headers["content-type"]` term literal being blanked, which
    // would add a second, capital "Content-Type: application/json" alongside it.
    const m = base();
    m.create.headers = { Authorization: "Bearer {auth:token}", "content-type": "application/xml" };
    const req = reqOf(m);
    expect(req.headers["content-type"]).toBe("application/xml");
    expect(req.headers["Content-Type"]).toBeUndefined();
  });

  it("defaults the write method to POST when the manifest omits it", () => {
    // Prevents the "POST" default literal being blanked (yielding an empty method).
    const m = base();
    delete m.create.method;
    expect(reqOf(m).method).toBe("POST");
  });

  it("the runtime guard refuses a DELETE with a message that names it", () => {
    // Prevents both LatchError message literals being blanked. Built via
    // manifestAdapter to bypass validateManifest, proving the interpreter's own
    // defense-in-depth. (manifestAdapter does not validate.)
    const m = base();
    m.create.method = "DELETE";
    let err: unknown;
    try {
      manifestAdapter(m).dryRun("example.com", [A_REC], AUTH);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(LatchError);
    expect((err as Error).message).toContain("DELETE");
  });
});

// ===========================================================================
// getByPath — via responseIdPath during a trusted apply.
// ===========================================================================
describe("getByPath (via responseIdPath)", () => {
  async function applyOne(response: Response) {
    const fetchMock = fetchFn(async () => response);
    const out = await manifestAdapter(base(), { trusted: true, fetch: fetchMock as unknown as typeof fetch }).apply(
      "example.com",
      [A_REC],
      AUTH,
    );
    return out;
  }

  it("returns no recordId (without throwing) when the path passes through null", () => {
    // Prevents the `acc == null || typeof acc !== "object"` guard being disabled
    // or its `||` -> `&&`: either would attempt `null["id"]` and throw a
    // TypeError instead of gracefully yielding undefined.
    return applyOne(okJson({ result: null })).then((out) => {
      expect(out.applied).toHaveLength(1);
      expect("recordId" in out.applied[0]!).toBe(false);
    });
  });

  it("NEGATIVE CONTROL: a resolvable path yields the id", () => {
    return applyOne(okJson({ result: { id: "rec-9" } })).then((out) => {
      expect(out.applied[0]!.recordId).toBe("rec-9");
    });
  });
});

// ===========================================================================
// apply — the write loop: recordId typing, manual rejection, HTTP auth gate.
// ===========================================================================
describe("apply (write loop)", () => {
  async function applyOne(response: Response, record: DnsRecord = A_REC) {
    const fetchMock = fetchFn(async () => response);
    const out = await manifestAdapter(base(), { trusted: true, fetch: fetchMock as unknown as typeof fetch }).apply(
      "example.com",
      [record],
      AUTH,
    );
    return { out, fetchMock };
  }

  it("stringifies a NUMERIC provider id into recordId", async () => {
    // Prevents `typeof id === "number"` -> `typeof id !== "number"`: a numeric id
    // must still be captured (as a string), not discarded.
    const { out } = await applyOne(okJson({ result: { id: 12345 } }));
    expect(out.applied[0]!.recordId).toBe("12345");
  });

  it("attaches NO recordId when the response carries none", async () => {
    // Prevents the id-type ternary being forced true, which would set
    // recordId: String(undefined) === "undefined".
    const { out } = await applyOne(okJson({ result: {} }));
    expect(out.applied).toHaveLength(1);
    expect("recordId" in out.applied[0]!).toBe(false);
  });

  it("routes a rejected record to manual carrying the record fields and a status note", async () => {
    // Prevents the pushed object being emptied to {} (losing the record) and the
    // note string being blanked. The note must name the provider and the status.
    const { out } = await applyOne(new Response("bad", { status: 400 }));
    expect(out.applied).toHaveLength(0);
    expect(out.manual).toHaveLength(1);
    expect(out.manual[0]!.type).toBe("A");
    expect(out.manual[0]!.host).toBe("@");
    expect(out.manual[0]!.value).toBe("1.2.3.4");
    expect(out.manual[0]!.note).toContain("400");
    expect(out.manual[0]!.note).toContain("Acme DNS");
  });

  it("throws provider_auth_failed on a 401 and on a 403 write, naming the provider", async () => {
    // Prevents the 401/403 guard collapsing, the `||` -> `&&`, and the message
    // being blanked. Both statuses are exercised so neither operand can be
    // silently disabled.
    for (const status of [401, 403]) {
      const err = (await applyOne(new Response("no", { status }))
        .then(() => null)
        .catch((e) => e)) as LatchError;
      expect(err).toBeInstanceOf(LatchError);
      expect(err.code).toBe("provider_auth_failed");
      expect(err.message).toContain("Acme DNS");
    }
  });
});

// ===========================================================================
// capabilities() — the automation gate and the descriptor fields.
// ===========================================================================
describe("capabilities()", () => {
  it("a trusted adapter with no explicit automation flag still advertises automated:true", () => {
    // Prevents `m.capabilities.automated ?? true` -> `?? false`: when the
    // manifest omits `automated`, a trusted adapter defaults to automated.
    const m = base();
    delete m.capabilities.automated;
    expect(manifestAdapter(m, { trusted: true }).capabilities().automated).toBe(true);
  });

  it("returns the full descriptor drawn from the manifest", () => {
    // Guards the id / displayName / authKind / record-type / apex passthrough.
    expect(manifestAdapter(base(), { trusted: true }).capabilities()).toEqual({
      id: "acme-dns",
      displayName: "Acme DNS",
      automated: true,
      authKind: "api_key",
      writesRecordTypes: ["A", "AAAA", "CNAME", "MX", "TXT"],
      supportsApex: true,
    });
  });
});

// ===========================================================================
// readExisting — request shape, auth/rejection paths, non-array tolerance,
// host normalization, and the default record map.
// ===========================================================================
describe("readExisting", () => {
  async function read(response: Response, manifest = base()) {
    const fetchMock = fetchFn(async () => response);
    const out = await manifestAdapter(manifest, { fetch: fetchMock as unknown as typeof fetch }).readExisting!("example.com", AUTH);
    return { out, fetchMock };
  }

  it("issues a GET to the joined URL with the substituted Authorization header", () => {
    // Prevents the fetch options object being emptied (losing method + headers),
    // the method default logic breaking, and toUpperCase -> toLowerCase.
    return read(okJson({ result: [] })).then(({ fetchMock }) => {
      const [url, init] = fetchMock.mock.calls[0]! as [string, RequestInit];
      expect(url).toBe("https://api.acme.test/v1/zones/zone-42/records");
      expect(init.method).toBe("GET");
      expect((init.headers as Record<string, string>).Authorization).toBe("Bearer acme-secret");
    });
  });

  it("defaults the read method to GET when the manifest omits it", () => {
    // Prevents the "GET" default literal being blanked and `?? "GET"` -> `&& "GET"`
    // (which yields undefined and throws in .toUpperCase()).
    const m = base();
    delete m.read!.method;
    return read(okJson({ result: [] }), m).then(({ fetchMock }) => {
      expect((fetchMock.mock.calls[0]![1] as RequestInit).method).toBe("GET");
    });
  });

  it("throws provider_auth_failed on 401 and 403, naming the provider", async () => {
    // Prevents the auth guard collapsing, the `||` and either status operand
    // being disabled, and the message being blanked.
    for (const status of [401, 403]) {
      const err = (await read(new Response("no", { status }))
        .then(() => null)
        .catch((e) => e)) as LatchError;
      expect(err).toBeInstanceOf(LatchError);
      expect(err.code).toBe("provider_auth_failed");
      expect(err.message).toContain("Acme DNS");
    }
  });

  it("throws provider_rejected on a non-2xx read, naming the provider", async () => {
    // Prevents the `!res.ok` guard being disabled and its message being blanked.
    const err = (await read(new Response("nope", { status: 500 }))
      .then(() => null)
      .catch((e) => e)) as LatchError;
    expect(err).toBeInstanceOf(LatchError);
    expect(err.code).toBe("provider_rejected");
    expect(err.message).toContain("Acme DNS");
  });

  it("returns [] when the records path does not resolve to an array", () => {
    // Prevents `if (!Array.isArray(rows)) return []` being forced false (which
    // would call .map on a non-array and throw) and the [] literal being seeded
    // with a bogus element.
    return read(okJson({ result: { not: "an array" } })).then(({ out }) => {
      expect(out).toEqual([]);
    });
  });

  it("folds both apex forms to \"@\" and leaves an out-of-zone name verbatim", () => {
    // toHost: prevents the trailing-dot template being blanked and the apex OR
    // collapsing (both "example.com" and "example.com." must fold), and prevents
    // the endsWith check being forced true / its `.${domain}` template blanked
    // (which would slice "other.org" down to "").
    const rows = [
      { type: "TXT", name: "example.com", content: "bare", ttl: 300 },
      { type: "TXT", name: "example.com.", content: "dotted", ttl: 300 },
      { type: "A", name: "other.org", content: "9.9.9.9", ttl: 300 },
      { type: "CNAME", name: "www.example.com", content: "t.acme.test", ttl: 300 },
    ];
    return read(okJson({ result: rows })).then(({ out }) => {
      expect(out.map((r) => r.host)).toEqual(["@", "@", "other.org", "www"]);
    });
  });

  it("uses the canonical default record map when the manifest omits recordMap", () => {
    // Prevents any DEFAULT_RECORD_MAP key literal being blanked (which would read
    // row[""] and stringify undefined) and the whole default object being emptied.
    const m = base();
    delete m.read!.recordMap;
    const rows = [
      { type: "A", host: "sub", value: "1.2.3.4", ttl: 300 },
      { type: "MX", host: "@", value: "mx.acme.test", ttl: 3600, priority: 5 },
    ];
    return read(okJson({ result: rows }), m).then(({ out }) => {
      expect(out).toEqual([
        { type: "A", host: "sub", value: "1.2.3.4", ttl: 300 },
        { type: "MX", host: "@", value: "mx.acme.test", ttl: 3600, priority: 5 },
      ]);
    });
  });
});

// ===========================================================================
// validateManifest — top-level shape.
// ===========================================================================
describe("validateManifest — top-level shape", () => {
  it("NEGATIVE CONTROL: a well-formed manifest validates ok", () => {
    // Guards every "always error" mutant across the whole function: if any guard
    // were forced to push unconditionally, this would fail.
    expect(validateManifest(base())).toEqual({ ok: true });
  });

  for (const [label, value] of [
    ["null", null],
    ["undefined", undefined],
    ["a primitive number", 42],
  ] as const) {
    it(`rejects ${label} with the object-required message`, () => {
      // Prevents the `m === null || typeof m !== "object"` guard collapsing (the
      // `&&` mutant proceeds to read .id off a non-object and throws) and the
      // returned { ok:false, errors:[...] } being mutated (ok flipped, errors
      // emptied, or the message blanked).
      expectFail(validateManifest(value), "manifest must be an object");
    });
  }
});

// ===========================================================================
// validateManifest — required string fields (typeof + non-empty guard).
// ===========================================================================
describe("validateManifest — required string fields", () => {
  const cases: Array<{ label: string; set: (m: AdapterManifest, v: unknown) => void; frag: string }> = [
    { label: "id", set: (m, v) => (loose(m).id = v), frag: "id:" },
    { label: "displayName", set: (m, v) => (loose(m).displayName = v), frag: "displayName:" },
    { label: "responseIdPath", set: (m, v) => (loose(m).responseIdPath = v), frag: "responseIdPath:" },
    { label: "create.path", set: (m, v) => (loose(m.create).path = v), frag: "create.path:" },
    { label: "read.path", set: (m, v) => (loose(m.read).path = v), frag: "read.path:" },
    { label: "read.recordsPath", set: (m, v) => (loose(m.read).recordsPath = v), frag: "read.recordsPath:" },
  ];

  for (const { label, set, frag } of cases) {
    it(`${label}: rejects a non-string value`, () => {
      // Prevents the `typeof X !== "string"` term being forced false and its
      // message being blanked.
      const m = base();
      set(m, 123);
      expectFail(validateManifest(m), frag);
    });

    it(`${label}: rejects an empty string`, () => {
      // Prevents the `X.trim() === ""` term being forced false and the `||` -> `&&`.
      const m = base();
      set(m, "");
      expectFail(validateManifest(m), frag);
    });

    it(`${label}: rejects a whitespace-only string`, () => {
      // Prevents the `.trim()` call being removed (which would compare "   " to ""
      // and wrongly accept it).
      const m = base();
      set(m, "   ");
      expectFail(validateManifest(m), frag);
    });
  }
});

// ===========================================================================
// validateManifest — authKind set membership.
// ===========================================================================
describe("validateManifest — authKind", () => {
  for (const kind of ["none", "oauth", "api_key", "iam", "domain_connect_sync"] as const) {
    it(`accepts the "${kind}" auth kind`, () => {
      // Prevents any AUTH_KINDS set literal being blanked (which would reject a
      // legitimate kind).
      const m = base();
      m.authKind = kind;
      expect(validateManifest(m)).toEqual({ ok: true });
    });
  }

  it("rejects an unknown auth kind", () => {
    // Prevents the membership check being forced false.
    const m = base();
    loose(m).authKind = "nope";
    expectFail(validateManifest(m), "authKind");
  });

  it("rejects a non-string auth kind", () => {
    const m = base();
    loose(m).authKind = 7;
    expectFail(validateManifest(m), "authKind");
  });
});

// ===========================================================================
// validateManifest — baseUrl.
// ===========================================================================
describe("validateManifest — baseUrl", () => {
  it("rejects a non-string baseUrl with the required-string message", () => {
    // Prevents the `typeof man.baseUrl !== "string"` guard being forced false
    // (which would route a number into URL parsing and report the wrong message)
    // and the "required string" message being blanked.
    const m = base();
    loose(m).baseUrl = 123;
    expectFail(validateManifest(m), "baseUrl: required string");
  });

  for (const url of ["ftp://acme.test", "file:///etc/passwd", "javascript:alert(1)", "not-a-url"]) {
    it(`rejects a non-http(s) baseUrl (${url})`, () => {
      // Prevents the protocol comparison being loosened; only http/https pass.
      const m = base();
      m.baseUrl = url;
      expectFail(validateManifest(m), "baseUrl");
    });
  }

  it("NEGATIVE CONTROL: an http baseUrl is accepted (protocol check not forced true)", () => {
    const m = base();
    m.baseUrl = "http://acme.test/v1";
    expect(validateManifest(m)).toEqual({ ok: true });
  });
});

// ===========================================================================
// validateManifest — capabilities.
// ===========================================================================
describe("validateManifest — capabilities", () => {
  it("rejects a missing capabilities object", () => {
    const m = base();
    delete loose(m).capabilities;
    expectFail(validateManifest(m), "capabilities: required object");
  });

  it("rejects a null capabilities object without throwing", () => {
    // The `&&` mutant would proceed to read .writesRecordTypes off null and throw.
    const m = base();
    loose(m).capabilities = null;
    expectFail(validateManifest(m), "capabilities");
  });

  it("rejects an empty writesRecordTypes array", () => {
    // Prevents `!Array.isArray(types) || types.length === 0` -> `&&` (which would
    // accept an empty list) and the message being blanked.
    const m = base();
    m.capabilities.writesRecordTypes = [];
    expectFail(validateManifest(m), "writesRecordTypes");
  });

  it("rejects a non-array writesRecordTypes", () => {
    const m = base();
    loose(m.capabilities).writesRecordTypes = "A";
    expectFail(validateManifest(m), "writesRecordTypes");
  });

  it("rejects an unknown record type inside writesRecordTypes", () => {
    // Prevents the `!DNS_RECORD_TYPES.has(t)` check being forced false.
    const m = base();
    loose(m.capabilities).writesRecordTypes = ["A", "ZZZ"];
    expectFail(validateManifest(m), "unknown type");
  });

  it("accepts the full set of known record types", () => {
    // Prevents any DNS_RECORD_TYPES set literal (e.g. "CAA", "NS") being blanked.
    const m = base();
    m.capabilities.writesRecordTypes = ["A", "AAAA", "CNAME", "CAA", "MX", "TXT", "NS"];
    expect(validateManifest(m)).toEqual({ ok: true });
  });

  it("rejects a non-boolean supportsApex", () => {
    // Prevents the `typeof ... !== "boolean"` check being forced false and its
    // message being blanked.
    const m = base();
    loose(m.capabilities).supportsApex = "yes";
    expectFail(validateManifest(m), "supportsApex");
  });
});

// ===========================================================================
// validateManifest — create block.
// ===========================================================================
describe("validateManifest — create", () => {
  it("rejects a null create block", () => {
    const m = base();
    loose(m).create = null;
    expectFail(validateManifest(m), "create");
  });

  it("rejects a DELETE method with the upsert-only message (not the generic one)", () => {
    // Prevents the DELETE literal being blanked / its branch forced false, which
    // would fall through to the generic "not allowed" message.
    const m = base();
    m.create.method = "DELETE";
    expectFail(validateManifest(m), "upsert-only");
  });

  it("rejects a non-allowlisted method, naming it", () => {
    // Prevents the `!ALLOWED_CREATE_METHODS.has(method)` branch being forced false
    // and the message (which interpolates the method) being blanked.
    const m = base();
    m.create.method = "OPTIONS";
    expectFail(validateManifest(m), "OPTIONS");
  });

  for (const method of ["POST", "PUT", "PATCH"]) {
    it(`accepts the ${method} method`, () => {
      // Prevents any ALLOWED_CREATE_METHODS set literal being blanked.
      const m = base();
      m.create.method = method;
      expect(validateManifest(m)).toEqual({ ok: true });
    });
  }

  it("accepts an omitted method (defaults to POST)", () => {
    // Prevents the "POST" default literal being blanked (which would fail the
    // allowlist check).
    const m = base();
    delete m.create.method;
    expect(validateManifest(m)).toEqual({ ok: true });
  });

  it("rejects a non-object headers value", () => {
    const m = base();
    loose(m.create).headers = "nope";
    expectFail(validateManifest(m), "create.headers");
  });

  it("rejects a non-string header value, naming the key", () => {
    // Prevents the per-entry `typeof v !== "string"` check being forced false and
    // its message being blanked.
    const m = base();
    loose(m.create).headers = { X: 123 };
    expectFail(validateManifest(m), "create.headers.X");
  });

  it("validates placeholders inside a header value (with the header label)", () => {
    // Prevents the `where` label passed to validatePlaceholders being blanked.
    const m = base();
    m.create.headers = { X: "{unknownZ}" };
    expectFail(validateManifest(m), "create.headers.X");
  });

  it("accepts an omitted headers block", () => {
    // Prevents `if (c.headers != null)` being forced true / `!=` -> `==`, which
    // would try to iterate absent headers and error or throw.
    const m = base();
    delete m.create.headers;
    expect(validateManifest(m)).toEqual({ ok: true });
  });

  it("rejects a missing bodyTemplate", () => {
    const m = base();
    delete loose(m.create).bodyTemplate;
    expectFail(validateManifest(m), "create.bodyTemplate");
  });

  it("rejects an unknown placeholder in the body with the body label", () => {
    // Prevents the body-template `where` label being blanked.
    const m = base();
    (m.create.bodyTemplate as Record<string, unknown>).evil = "{__proto__}";
    expectFail(validateManifest(m), "create.bodyTemplate");
  });

  it("rejects an unknown placeholder nested inside a body OBJECT", () => {
    // Prevents stringLeaves' object branch being skipped, which would hide a bad
    // placeholder buried one level down.
    const m = base();
    m.create.bodyTemplate = { outer: { inner: "{unknownO}" } };
    expectFail(validateManifest(m), "unknown placeholder");
  });

  it("rejects an unknown placeholder nested inside a body ARRAY", () => {
    // Prevents stringLeaves' `Array.isArray` branch being forced false, which
    // would hide a bad placeholder inside an array leaf.
    const m = base();
    m.create.bodyTemplate = { list: ["{unknownA}"] };
    expectFail(validateManifest(m), "unknown placeholder");
  });

  it("accepts primitive / null body leaves without treating them as placeholders", () => {
    // Prevents stringLeaves' object guard being forced true or `&&` -> `||`
    // (a null leaf would make Object.values(null) throw during validation).
    const m = base();
    m.create.bodyTemplate = { a: "{type}", b: null, c: 42, d: true };
    expect(validateManifest(m)).toEqual({ ok: true });
  });
});

// ===========================================================================
// validateManifest — read block (optional).
// ===========================================================================
describe("validateManifest — read", () => {
  it("accepts a manifest with no read block", () => {
    // Prevents `if (read != null)` being forced true, which would validate an
    // absent read and report "read: must be an object".
    const m = base();
    delete m.read;
    expect(validateManifest(m)).toEqual({ ok: true });
  });

  it("rejects a non-object read block with the specific message", () => {
    // Prevents the `typeof read !== "object"` guard being forced false (which
    // would produce a different, misleading message).
    const m = base();
    loose(m).read = "nope";
    expectFail(validateManifest(m), "read: must be an object");
  });

  it("rejects a DELETE read method", () => {
    const m = base();
    m.read!.method = "DELETE";
    expectFail(validateManifest(m), "DELETE");
  });

  it("rejects a non-allowlisted read method (naming GET/POST)", () => {
    // Prevents the `!ALLOWED_READ_METHODS.has(method)` branch being forced false
    // and the message being blanked.
    const m = base();
    m.read!.method = "PUT";
    expectFail(validateManifest(m), "GET/POST");
  });

  for (const method of ["GET", "POST"]) {
    it(`accepts the ${method} read method`, () => {
      // Prevents any ALLOWED_READ_METHODS set literal being blanked.
      const m = base();
      m.read!.method = method;
      expect(validateManifest(m)).toEqual({ ok: true });
    });
  }

  it("accepts an omitted read method (defaults to GET)", () => {
    const m = base();
    delete m.read!.method;
    expect(validateManifest(m)).toEqual({ ok: true });
  });

  it("rejects a non-object read headers value", () => {
    const m = base();
    loose(m.read).headers = "nope";
    expectFail(validateManifest(m), "read.headers");
  });

  it("rejects a non-string read header value, naming the key", () => {
    const m = base();
    loose(m.read).headers = { X: 123 };
    expectFail(validateManifest(m), "read.headers.X");
  });
});

// ===========================================================================
// validatePlaceholders — the empty auth placeholder rule.
// ===========================================================================
describe("validatePlaceholders — empty auth placeholder", () => {
  it("rejects an empty {auth:} placeholder", () => {
    // Prevents `token.length <= "auth:".length` -> `<` (which would accept the
    // empty key), the branch being disabled, the "auth:" literal being blanked,
    // and the message being blanked.
    const m = base();
    m.create.headers = { X: "{auth:}" };
    expectFail(validateManifest(m), "empty auth placeholder");
  });

  it("NEGATIVE CONTROL: a named {auth:token} placeholder is accepted", () => {
    // Guards the rule above from flagging a legitimate, non-empty auth key.
    const m = base();
    m.create.headers = { X: "Bearer {auth:token}" };
    expect(validateManifest(m)).toEqual({ ok: true });
  });

  it("rejects an auth placeholder in the body (auth not allowed there)", () => {
    // Prevents the allowAuth argument being ignored for the body template.
    const m = base();
    (m.create.bodyTemplate as Record<string, unknown>).token = "{auth:token}";
    expectFail(validateManifest(m), "not allowed");
  });
});

// ===========================================================================
// registerManifestAdapter — validate, then register.
// ===========================================================================
describe("registerManifestAdapter", () => {
  it("validates, registers, and returns the live adapter", () => {
    // Prevents the whole function body being emptied (which returns undefined and
    // registers nothing). registerAdapter is mocked, so this asserts the call
    // without touching the shared registry.
    const m = base();
    m.id = "acme-register-probe";
    const adapter = registerManifestAdapter(m, { trusted: true });
    expect(adapter).toBeDefined();
    expect(adapter.manifest.id).toBe("acme-register-probe");
    expect(typeof adapter.apply).toBe("function");
    expect(registerAdapter).toHaveBeenCalledTimes(1);
    expect((vi.mocked(registerAdapter).mock.calls[0]![0] as ManifestAdapter).manifest.id).toBe(
      "acme-register-probe",
    );
  });

  it("throws on an invalid manifest, and does NOT register it", () => {
    // Prevents `if (!check.ok)` being negated / forced false: an invalid manifest
    // must be refused before registration.
    const m = base();
    m.id = "acme-bad";
    m.baseUrl = "ftp://acme.test";
    expect(() => registerManifestAdapter(m)).toThrow(LatchError);
    expect(registerAdapter).not.toHaveBeenCalled();
  });

  it("names the offending manifest id and its errors in the thrown message", () => {
    // Prevents the message template being blanked and `id ?? "?"` -> `id && "?"`
    // (which would print "?" in place of the real id).
    const m = base();
    m.id = "acme-bad-2";
    m.baseUrl = "ftp://acme.test";
    let err: unknown;
    try {
      registerManifestAdapter(m);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(LatchError);
    expect((err as Error).message).toContain("invalid manifest");
    expect((err as Error).message).toContain("acme-bad-2");
    expect((err as Error).message).toContain("baseUrl");
  });

  it("NEGATIVE CONTROL: a valid manifest does not throw", () => {
    // Guards the throw-tests above from a mutant that always throws.
    const m = base();
    m.id = "acme-register-ok";
    expect(() => registerManifestAdapter(m, { trusted: true })).not.toThrow();
  });
});
