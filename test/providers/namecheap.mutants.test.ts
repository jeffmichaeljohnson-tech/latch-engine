// Latch — Namecheap adapter: mutation-hardening tests.
//
// Companion to namecheap.test.ts and namecheap-txt-slot.test.ts. Those pin the
// getHosts -> union -> setHosts happy path and the TXT-slot union rule; this one
// closes the mutants that survived them: the auth reader's per-field guard, the
// domain split, the canonical host normalization, the getHosts XML parse
// (status, error message, per-row attribute extraction, self-closing
// tolerance), the setHosts request shape and its auth/error paths, the exposed
// capability constants, and the whitespace/anchor details of the TXT-slot regex.
// Each test says WHICH defect it prevents, and each group carries a negative
// control so a function that always returns the positive answer cannot pass.
//
// No test performs a real network call: fetch is stubbed for every case. Most
// internal helpers (readAuth, splitDomain, toNamecheapHost, parseHosts,
// toHostRow, buildSetHostsBody) are not exported, so they are exercised through
// apply() and observed via the setHosts request body; unionHosts is exported and
// is driven directly for the TXT-slot cases.

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  NamecheapAdapter,
  NAMECHEAP_CAPABILITIES,
  unionHosts,
} from "../../src/providers/namecheap";
import { LatchError } from "../../src/types";
import type { DnsRecord } from "../../src/types";

const NAMECHEAP_API = "https://api.namecheap.com/xml.response";

const AUTH = {
  apiUser: "gbuild",
  apiKey: "nc-secret",
  userName: "gbuild",
  clientIp: "203.0.113.7",
};

afterEach(() => vi.unstubAllGlobals());

// --- getHosts fixtures -----------------------------------------------------

// A Status="OK" response with no host rows: existing set is empty, so the
// setHosts body reflects only the incoming records (clean indexing).
const GET_EMPTY_OK = `<?xml version="1.0" encoding="utf-8"?>
<ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response">
  <CommandResponse Type="namecheap.domains.dns.getHosts">
    <DomainDNSGetHostsResult Domain="example.com" IsUsingOurDNS="true"></DomainDNSGetHostsResult>
  </CommandResponse>
</ApiResponse>`;

const SET_OK = `<?xml version="1.0" encoding="utf-8"?>
<ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response">
  <CommandResponse Type="namecheap.domains.dns.setHosts">
    <DomainDNSSetHostsResult Domain="example.com" IsSuccess="true" />
  </CommandResponse>
</ApiResponse>`;

// --- helpers ---------------------------------------------------------------

/** Stub fetch to answer getHosts (call 1) then setHosts (call 2). */
function stubFetch(get: Response, set: Response) {
  const m = vi.fn().mockResolvedValueOnce(get).mockResolvedValueOnce(set);
  vi.stubGlobal("fetch", m);
  return m;
}

function parseSetHostsBody(body: string): Record<string, string> {
  return Object.fromEntries(new URLSearchParams(body));
}

interface BodyHost {
  name?: string;
  type?: string;
  address?: string;
  ttl?: string;
  mxPref?: string;
}

/** Decode the numbered HostNameN / RecordTypeN / … fields back into rows. */
function bodyHosts(params: Record<string, string>): BodyHost[] {
  const rows: BodyHost[] = [];
  for (let i = 1; params[`HostName${i}`] !== undefined; i++) {
    rows.push({
      name: params[`HostName${i}`],
      type: params[`RecordType${i}`],
      address: params[`Address${i}`],
      ttl: params[`TTL${i}`],
      mxPref: params[`MXPref${i}`],
    });
  }
  return rows;
}

/** Run apply() with fetch stubbed and return the decoded setHosts body. */
async function applyAndReadBody(
  records: DnsRecord[],
  opts?: { getXml?: string; domain?: string },
): Promise<{ params: Record<string, string>; hosts: BodyHost[]; mock: ReturnType<typeof stubFetch> }> {
  const mock = stubFetch(
    new Response(opts?.getXml ?? GET_EMPTY_OK, { status: 200 }),
    new Response(SET_OK, { status: 200 }),
  );
  await new NamecheapAdapter().apply(opts?.domain ?? "example.com", records, AUTH);
  const params = parseSetHostsBody(mock.mock.calls[1]![1]!.body as string);
  return { params, hosts: bodyHosts(params), mock };
}

const A = (host: string, value: string): DnsRecord => ({ type: "A", host, value, ttl: 1800 });

// ===========================================================================
// Capability surface — the exported constant a caller reads to decide routing.
// ===========================================================================
describe("NAMECHEAP_CAPABILITIES", () => {
  it("advertises the real identity, automation flag, apex support and record set", () => {
    // Prevents: displayName blanked to "", automated flipped to false,
    // supportsApex flipped to true, and writesRecordTypes emptied or any single
    // element blanked — each would mislead the router about what this adapter can do.
    expect(NAMECHEAP_CAPABILITIES.id).toBe("namecheap");
    expect(NAMECHEAP_CAPABILITIES.displayName).toBe("Namecheap");
    expect(NAMECHEAP_CAPABILITIES.automated).toBe(true);
    expect(NAMECHEAP_CAPABILITIES.supportsApex).toBe(false);
    expect(NAMECHEAP_CAPABILITIES.writesRecordTypes).toEqual([
      "A",
      "AAAA",
      "CNAME",
      "CAA",
      "MX",
      "TXT",
      "NS",
    ]);
  });

  it("capabilities() returns that same descriptor, not undefined", () => {
    // Prevents: the method body being emptied so capabilities() returns undefined.
    // Negative control: a distinct object with the wrong id would also fail.
    expect(new NamecheapAdapter().capabilities()).toEqual(NAMECHEAP_CAPABILITIES);
    expect(new NamecheapAdapter().capabilities().id).toBe("namecheap");
  });
});

// ===========================================================================
// readAuth — the per-field credential guard, reached through apply().
// ===========================================================================
describe("apply — credential validation (readAuth)", () => {
  async function applyErr(auth: unknown): Promise<unknown> {
    // fetch is stubbed so that if the guard WRONGLY passes, apply resolves
    // (returning a non-error) rather than hitting the network — a resolved value
    // then fails the LatchError assertions below.
    stubFetch(new Response(GET_EMPTY_OK, { status: 200 }), new Response(SET_OK, { status: 200 }));
    return new NamecheapAdapter()
      .apply("example.com", [A("@", "1.2.3.4")], auth as never)
      .then(
        (ok) => ok as unknown,
        (e) => e as unknown,
      );
  }

  it("undefined auth rejects with a LatchError, not a raw TypeError", async () => {
    // Prevents: the auth?.[...] optional chaining being weakened to auth[...],
    // which throws "Cannot read properties of undefined" instead of the typed
    // provider_auth_failed error the caller is contracted to receive.
    const err = await applyErr(undefined);
    expect(err).toBeInstanceOf(LatchError);
    expect((err as LatchError).code).toBe("provider_auth_failed");
    expect((err as Error).message).toMatch(/apiUser/);
  });

  // Each row leaves exactly ONE field invalid so it isolates that operand of the
  // OR guard. Prevents: any single typeof check being disabled (-> false), and
  // any || being turned into && (which would only throw when several fields fail
  // at once). userName is defaulted from apiUser, so it is made invalid with a
  // non-string rather than by omission.
  const badAuths: Array<[string, Record<string, unknown>]> = [
    ["apiUser missing", { apiKey: "k", userName: "u", clientIp: "1.1.1.1" }],
    ["apiKey missing", { apiUser: "a", userName: "u", clientIp: "1.1.1.1" }],
    ["clientIp missing", { apiUser: "a", apiKey: "k", userName: "u" }],
    ["userName not a string", { apiUser: "a", apiKey: "k", userName: 123, clientIp: "1.1.1.1" }],
  ];
  for (const [label, auth] of badAuths) {
    it(`rejects provider_auth_failed when ${label}`, async () => {
      const err = await applyErr(auth);
      expect(err).toBeInstanceOf(LatchError);
      expect((err as LatchError).code).toBe("provider_auth_failed");
      expect((err as Error).message).toMatch(/Namecheap adapter requires/);
    });
  }

  it("negative control: fully valid auth does NOT reject", async () => {
    // If any guard test passed only because apply always throws, this would fail.
    const err = await applyErr(AUTH);
    expect(err).not.toBeInstanceOf(Error);
  });

  it("userName defaults to apiUser when omitted (and reaches the request body)", async () => {
    // Prevents: the `?? apiUser` default being turned into `&& apiUser` (which
    // yields undefined and throws) or the default source being blanked to "".
    const { params } = await applyAndReadBody([A("@", "1.2.3.4")], undefined);
    // AUTH here supplies userName; use a userName-less auth for the real check:
    const mock = stubFetch(
      new Response(GET_EMPTY_OK, { status: 200 }),
      new Response(SET_OK, { status: 200 }),
    );
    await new NamecheapAdapter().apply(
      "example.com",
      [A("@", "1.2.3.4")],
      { apiUser: "solo-user", apiKey: "k", clientIp: "1.1.1.1" } as never,
    );
    const p2 = parseSetHostsBody(mock.mock.calls[1]![1]!.body as string);
    expect(p2.UserName).toBe("solo-user");
    // sanity: the first (AUTH-based) body carried its explicit userName
    expect(params.UserName).toBe("gbuild");
  });
});

// ===========================================================================
// splitDomain — reached through apply() (used for SLD/TLD and in the body).
// ===========================================================================
describe("apply — domain split (splitDomain)", () => {
  it("rejects provider_rejected with the offending domain in the message", async () => {
    // Prevents: the `dot < 0` guard being disabled (-> false) so a dotless
    // domain slips through, and the error code / interpolated message being blanked.
    stubFetch(new Response(GET_EMPTY_OK, { status: 200 }), new Response(SET_OK, { status: 200 }));
    const err = await new NamecheapAdapter()
      .apply("nodot", [A("@", "1.2.3.4")], AUTH)
      .catch((e) => e as unknown);
    expect(err).toBeInstanceOf(LatchError);
    expect((err as LatchError).code).toBe("provider_rejected");
    expect((err as Error).message).toMatch(/Invalid domain: nodot/);
  });

  it("a leading-dot domain is NOT rejected (dot at index 0 is valid)", async () => {
    // Prevents: `dot < 0` being loosened to `dot <= 0`, which would reject a
    // domain whose first character is a dot. Pins that indexOf(".") === 0 splits
    // into an empty SLD rather than throwing. (Edge input, deliberately chosen to
    // separate `< 0` from `<= 0`.)
    const { params } = await applyAndReadBody([A("@", "1.2.3.4")], { domain: ".com" });
    expect(params.SLD).toBe("");
    expect(params.TLD).toBe("com");
  });
});

// ===========================================================================
// toNamecheapHost — canonical host -> Namecheap label, observed as HostNameN.
// ===========================================================================
describe("apply — host normalization (toNamecheapHost)", () => {
  it("apex forms all collapse to '@'", async () => {
    // Prevents: the apex `if` being forced false (so "" / domain never map to
    // "@"), the return literal being blanked, and the "" / "@" comparisons being
    // inverted.
    const { hosts } = await applyAndReadBody([
      A("", "1.0.0.1"),
      A("@", "1.0.0.2"),
      A("example.com", "1.0.0.3"),
    ]);
    expect(hosts.find((h) => h.address === "1.0.0.1")!.name).toBe("@");
    expect(hosts.find((h) => h.address === "1.0.0.2")!.name).toBe("@");
    expect(hosts.find((h) => h.address === "1.0.0.3")!.name).toBe("@");
  });

  it("an FQDN under the domain is stripped to its label; a bare label is kept", async () => {
    // Prevents: the `if` being forced true (so a bare label wrongly becomes "@"),
    // endsWith swapped for startsWith, the suffix template blanked (endsWith("")
    // is always true), and the slice length arithmetic being altered (+/-1 or sign).
    const { hosts } = await applyAndReadBody([
      A("www.example.com", "1.0.0.4"),
      A("a.b.example.com", "1.0.0.5"),
      A("blog", "1.0.0.6"),
    ]);
    expect(hosts.find((h) => h.address === "1.0.0.4")!.name).toBe("www");
    expect(hosts.find((h) => h.address === "1.0.0.5")!.name).toBe("a.b");
    // Negative control: a bare label must pass through unchanged, not be stripped
    // to "" or promoted to "@".
    expect(hosts.find((h) => h.address === "1.0.0.6")!.name).toBe("blog");
  });
});

// ===========================================================================
// apply — the setHosts request itself: endpoint, method, headers, credentials,
// command, SLD/TLD, TTL, MX default, and the returned manual list.
// ===========================================================================
describe("apply — setHosts request shape", () => {
  it("posts form-urlencoded to the Namecheap endpoint with the right command and creds", async () => {
    const mock = stubFetch(
      new Response(GET_EMPTY_OK, { status: 200 }),
      new Response(SET_OK, { status: 200 }),
    );
    const out = await new NamecheapAdapter().apply(
      "example.com",
      [A("www", "1.2.3.4")],
      AUTH,
    );

    // getHosts is a GET against the real endpoint; setHosts is a POST to it.
    // Prevents: the endpoint constant being blanked to "".
    expect(String(mock.mock.calls[0]![0])).toContain(NAMECHEAP_API);
    expect(String(mock.mock.calls[0]![0])).toContain("Command=namecheap.domains.dns.getHosts");
    expect(mock.mock.calls[1]![0]).toBe(NAMECHEAP_API);

    const init = mock.mock.calls[1]![1]!;
    expect(init.method).toBe("POST");
    // Prevents: the headers object being emptied, or the content-type string blanked.
    expect((init.headers as Record<string, string>)["Content-Type"]).toBe(
      "application/x-www-form-urlencoded",
    );

    const params = parseSetHostsBody(init.body as string);
    // Prevents: any of the four credential field NAMES being blanked to "" (which
    // would drop the credential), and readAuth returning {} instead of the creds.
    expect(params.ApiUser).toBe("gbuild");
    expect(params.ApiKey).toBe("nc-secret");
    expect(params.UserName).toBe("gbuild");
    expect(params.ClientIp).toBe("203.0.113.7");
    expect(params.Command).toBe("namecheap.domains.dns.setHosts");
    expect(params.SLD).toBe("example");
    expect(params.TLD).toBe("com");

    // Prevents: the manual array being seeded with a bogus element.
    expect(out.manual).toEqual([]);
    expect(out.applied).toHaveLength(1);
    expect(out.applied[0]!.type).toBe("A");
  });

  it("writes an explicit TTL for each host", async () => {
    // Prevents: the `TTL${n}` key being blanked so no TTL is ever sent.
    const { hosts } = await applyAndReadBody([{ type: "A", host: "t", value: "9.9.9.9", ttl: 4242 }]);
    expect(hosts.find((h) => h.address === "9.9.9.9")!.ttl).toBe("4242");
  });

  it("an incoming MX carries its priority; a non-MX carries no MXPref", async () => {
    // Prevents: the MX guard in toHostRow being disabled/inverted (so priority is
    // dropped), the mxPref object being emptied, and `h.mxPref ?? 10` becoming
    // `h.mxPref && 10` (which would coerce a real 20 down to 10).
    const { hosts } = await applyAndReadBody([
      { type: "MX", host: "@", value: "mail.example.net.", ttl: 1800, priority: 20 },
      A("plainA", "5.5.5.5"),
    ]);
    const mx = hosts.find((h) => h.type === "MX")!;
    expect(mx.mxPref).toBe("20");
    // Negative control: an A record must not acquire an MXPref field.
    expect(hosts.find((h) => h.address === "5.5.5.5")!.mxPref).toBeUndefined();
  });

  it("an MX with no priority defaults to MXPref 10 (not NaN, not undefined)", async () => {
    // Prevents: the emit-time guard `h.type === "MX"` being forced true for every
    // row is covered above; here we pin the default path so the ?? fallback yields
    // the literal 10.
    const { hosts } = await applyAndReadBody([
      { type: "MX", host: "@", value: "mail2.example.net.", ttl: 1800 },
    ]);
    expect(hosts.find((h) => h.type === "MX")!.mxPref).toBe("10");
  });
});

// ===========================================================================
// parseHosts — existing rows read back from getHosts and carried into setHosts.
// ===========================================================================
describe("apply — parsing the existing host set (parseHosts)", () => {
  // Rich existing set. HostId is first, so a mutant that reads the FIRST attribute
  // instead of the named one (attr(frag, "") ) would pick up "10x" rather than the
  // Name/TTL. TTLs and MXPrefs are distinct from the defaults so a fallback shows.
  const GET_RICH = `<?xml version="1.0" encoding="utf-8"?>
<ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response">
  <CommandResponse Type="namecheap.domains.dns.getHosts">
    <DomainDNSGetHostsResult Domain="example.com" IsUsingOurDNS="true">
      <host HostId="101" Name="keep" Type="A" Address="10.0.0.1" TTL="3600" />
      <host HostId="102" Name="@" Type="MX" Address="mx1.example.net." MXPref="20" TTL="1800" />
      <host HostId="103" Name="@" Type="MX" Address="mx2.example.net." TTL="1800" />
      <host HostId="104" Name="notll" Type="TXT" Address="just-a-token" />
    </DomainDNSGetHostsResult>
  </CommandResponse>
</ApiResponse>`;

  it("preserves unrelated existing rows with their names, TTLs and MX prefs intact", async () => {
    // The incoming CNAME at "shop" overlaps nothing, so all four existing rows
    // survive the union and reappear in the setHosts body.
    // Prevents: attr() reading the wrong attribute (Name/TTL), the whole attr
    // regex being blanked (all rows dropped), the mxPref/ttl ternaries defaulting
    // or NaN-ing, and the equality checks flipping.
    const { hosts } = await applyAndReadBody(
      [{ type: "CNAME", host: "shop", value: "shops.example.net.", ttl: 300 }],
      { getXml: GET_RICH },
    );

    const keep = hosts.find((h) => h.address === "10.0.0.1")!;
    expect(keep.name).toBe("keep"); // not "101" (the HostId)
    expect(keep.ttl).toBe("3600"); // parsed TTL, not the 1800 default and not NaN

    const mx1 = hosts.find((h) => h.address === "mx1.example.net.")!;
    expect(mx1.mxPref).toBe("20"); // parsed MXPref, not the 10 default

    const mx2 = hosts.find((h) => h.address === "mx2.example.net.")!;
    expect(mx2.mxPref).toBe("10"); // no MXPref attribute -> default 10, never "NaN"

    const txt = hosts.find((h) => h.address === "just-a-token")!;
    expect(txt.ttl).toBe("1800"); // no TTL attribute -> 1800 default, never "NaN"

    // Negative control: the new CNAME is present, so this is a real union not a
    // pass-through of only the existing rows.
    expect(hosts.some((h) => h.address === "shops.example.net.")).toBe(true);
    expect(hosts).toHaveLength(5);
  });

  it("drops host rows missing Name, Type or Address", async () => {
    // Prevents: the `if (... === undefined) continue` guard being disabled or its
    // OR turned into AND, which would keep incomplete rows (emitting HostName /
    // RecordType / Address of "undefined").
    const getXml = `<?xml version="1.0" encoding="utf-8"?>
<ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response">
  <CommandResponse Type="namecheap.domains.dns.getHosts">
    <DomainDNSGetHostsResult Domain="example.com">
      <host HostId="1" Name="good" Type="A" Address="1.1.1.1" TTL="1800" />
      <host HostId="2" Type="A" Address="2.2.2.2" TTL="1800" />
      <host HostId="3" Name="notype" Address="3.3.3.3" TTL="1800" />
      <host HostId="4" Name="noaddr" Type="A" TTL="1800" />
    </DomainDNSGetHostsResult>
  </CommandResponse>
</ApiResponse>`;
    const { hosts } = await applyAndReadBody([A("zzz", "8.8.8.8")], { getXml });
    expect(hosts.some((h) => h.address === "1.1.1.1")).toBe(true);
    expect(hosts.some((h) => h.address === "2.2.2.2")).toBe(false);
    expect(hosts.some((h) => h.address === "3.3.3.3")).toBe(false);
    // Negative control: the only complete existing row plus the incoming = 2.
    expect(hosts.some((h) => h.name === "undefined")).toBe(false);
    expect(hosts).toHaveLength(2);
  });

  it("parses a non-self-closing <host ...> element too", async () => {
    // Prevents: the host regex requiring a self-closing slash (`\/>` instead of
    // `\/?>`), which would silently drop any row written with a separate close tag.
    const getXml = `<?xml version="1.0" encoding="utf-8"?>
<ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response">
  <CommandResponse Type="namecheap.domains.dns.getHosts">
    <DomainDNSGetHostsResult Domain="example.com">
      <host HostId="1" Name="plain" Type="A" Address="7.7.7.7" TTL="1800"></host>
    </DomainDNSGetHostsResult>
  </CommandResponse>
</ApiResponse>`;
    const { hosts } = await applyAndReadBody([A("zzz", "8.8.8.8")], { getXml });
    expect(hosts.some((h) => h.address === "7.7.7.7")).toBe(true);
  });

  it("tolerates a getHosts response with no ApiResponse Status attribute", async () => {
    // Prevents: the `?.[1]` on the status match being made non-optional, which
    // would throw a TypeError when the regex finds no Status rather than treating
    // the absence as "no error to report".
    const getXml = `<?xml version="1.0" encoding="utf-8"?>
<ApiResponse xmlns="http://api.namecheap.com/xml.response">
  <CommandResponse Type="namecheap.domains.dns.getHosts">
    <DomainDNSGetHostsResult Domain="example.com">
      <host HostId="1" Name="ok" Type="A" Address="6.6.6.6" TTL="1800" />
    </DomainDNSGetHostsResult>
  </CommandResponse>
</ApiResponse>`;
    const { hosts } = await applyAndReadBody([A("zzz", "8.8.8.8")], { getXml });
    expect(hosts.some((h) => h.address === "6.6.6.6")).toBe(true);
  });
});

// ===========================================================================
// getHosts error handling — the status check and the extracted error message.
// The <ApiResponse> tag deliberately places xmlns BEFORE Status so that a regex
// that stops matching after one character (or on `>` only) fails to read the
// status and is caught.
// ===========================================================================
describe("apply — getHosts error responses", () => {
  it("surfaces the provider's error message on a Status=ERROR getHosts", async () => {
    // Prevents: the status regex being narrowed so ERROR is never seen (the check
    // is skipped), the status check being disabled, the error-message regex being
    // narrowed to yield the default, the `?? default` becoming `&& default`, and
    // the error code being blanked.
    const getXml = `<?xml version="1.0" encoding="utf-8"?>
<ApiResponse xmlns="http://api.namecheap.com/xml.response" Status="ERROR">
  <Errors><Error Number="2030166">Zone file not found</Error></Errors>
</ApiResponse>`;
    stubFetch(new Response(getXml, { status: 200 }), new Response(SET_OK, { status: 200 }));
    const err = await new NamecheapAdapter()
      .apply("example.com", [A("@", "1.2.3.4")], AUTH)
      .catch((e) => e as unknown);
    expect(err).toBeInstanceOf(LatchError);
    expect((err as LatchError).code).toBe("provider_rejected");
    expect((err as Error).message).toBe("Zone file not found");
  });

  it("falls back to a default message when Status=ERROR carries no <Error>", async () => {
    // Prevents: the `?.[1]` on the error match being made non-optional (TypeError
    // when there is no <Error>), and the default message string being blanked.
    const getXml = `<?xml version="1.0" encoding="utf-8"?>
<ApiResponse xmlns="http://api.namecheap.com/xml.response" Status="ERROR"></ApiResponse>`;
    stubFetch(new Response(getXml, { status: 200 }), new Response(SET_OK, { status: 200 }));
    const err = await new NamecheapAdapter()
      .apply("example.com", [A("@", "1.2.3.4")], AUTH)
      .catch((e) => e as unknown);
    expect(err).toBeInstanceOf(LatchError);
    expect((err as LatchError).code).toBe("provider_rejected");
    expect((err as Error).message).toMatch(/getHosts failed/);
  });

  it("negative control: a Status=OK getHosts does not reject", async () => {
    const out = await applyAndReadBody([A("@", "1.2.3.4")]);
    expect(out.hosts.length).toBeGreaterThan(0);
  });
});

// ===========================================================================
// apply — the two HTTP auth gates and the setHosts error path.
// ===========================================================================
describe("apply — HTTP auth failures and setHosts errors", () => {
  for (const status of [401, 403]) {
    it(`rejects provider_auth_failed when getHosts returns ${status}`, async () => {
      // Prevents: the 401/403 block being emptied, the condition forced false, the
      // `||` turned into `&&`, and EITHER status operand being individually
      // disabled (that is why both 401 and 403 are exercised).
      stubFetch(new Response("", { status }), new Response(SET_OK, { status: 200 }));
      const err = await new NamecheapAdapter()
        .apply("example.com", [A("@", "1.2.3.4")], AUTH)
        .catch((e) => e as unknown);
      expect(err).toBeInstanceOf(LatchError);
      expect((err as LatchError).code).toBe("provider_auth_failed");
      expect((err as Error).message).toMatch(/credentials/);
    });

    it(`rejects provider_auth_failed when setHosts returns ${status}`, async () => {
      stubFetch(new Response(GET_EMPTY_OK, { status: 200 }), new Response("", { status }));
      const err = await new NamecheapAdapter()
        .apply("example.com", [A("@", "1.2.3.4")], AUTH)
        .catch((e) => e as unknown);
      expect(err).toBeInstanceOf(LatchError);
      expect((err as LatchError).code).toBe("provider_auth_failed");
      expect((err as Error).message).toMatch(/credentials/);
    });
  }

  it("surfaces the provider's error on a Status=ERROR setHosts (HTTP 200)", async () => {
    // Prevents: the setHosts status regex being narrowed, the error-message regex
    // being narrowed to the default, and the `?? default` becoming `&& default`.
    const setXml = `<?xml version="1.0" encoding="utf-8"?>
<ApiResponse xmlns="http://api.namecheap.com/xml.response" Status="ERROR">
  <Errors><Error Number="4022336">Too many records</Error></Errors>
</ApiResponse>`;
    stubFetch(new Response(GET_EMPTY_OK, { status: 200 }), new Response(setXml, { status: 200 }));
    const err = await new NamecheapAdapter()
      .apply("example.com", [A("@", "1.2.3.4")], AUTH)
      .catch((e) => e as unknown);
    expect(err).toBeInstanceOf(LatchError);
    expect((err as LatchError).code).toBe("provider_rejected");
    expect((err as Error).message).toBe("Too many records");
  });

  it("falls back to a default message on a Status=ERROR setHosts with no <Error>", async () => {
    // Prevents: the `?.[1]` on the setHosts error match being made non-optional,
    // and the default setHosts message being blanked.
    const setXml = `<?xml version="1.0" encoding="utf-8"?>
<ApiResponse xmlns="http://api.namecheap.com/xml.response" Status="ERROR"></ApiResponse>`;
    stubFetch(new Response(GET_EMPTY_OK, { status: 200 }), new Response(setXml, { status: 200 }));
    const err = await new NamecheapAdapter()
      .apply("example.com", [A("@", "1.2.3.4")], AUTH)
      .catch((e) => e as unknown);
    expect(err).toBeInstanceOf(LatchError);
    expect((err as LatchError).code).toBe("provider_rejected");
    expect((err as Error).message).toMatch(/setHosts failed/);
  });

  it("tolerates a setHosts 200 response with no ApiResponse Status", async () => {
    // Prevents: the `?.[1]` on the setHosts status match being made non-optional,
    // which would throw when a success response happens to omit Status.
    const setXml = `<?xml version="1.0" encoding="utf-8"?>
<ApiResponse xmlns="http://api.namecheap.com/xml.response">
  <CommandResponse Type="namecheap.domains.dns.setHosts">
    <DomainDNSSetHostsResult Domain="example.com" IsSuccess="true" />
  </CommandResponse>
</ApiResponse>`;
    stubFetch(new Response(GET_EMPTY_OK, { status: 200 }), new Response(setXml, { status: 200 }));
    const out = await new NamecheapAdapter().apply("example.com", [A("@", "1.2.3.4")], AUTH);
    expect(out.applied).toHaveLength(1);
  });
});

// ===========================================================================
// unionHosts / txtSlot — the TXT-slot regex whitespace and anchor details.
// These use the exported unionHosts directly. A TXT slot is `v=<tag>` only when
// the value BEGINS with a v= tag (whitespace/quote tolerated); anything else is
// its own slot keyed by the trimmed value.
// ===========================================================================
describe("unionHosts — TXT slot regex boundaries (txtSlot)", () => {
  type Row = { name: string; type: string; address: string; ttl: number };
  const row = (address: string, name = "@"): Row => ({ name, type: "TXT", address, ttl: 1800 });
  const addrs = (rows: Row[]) => rows.map((r) => r.address);
  const NEW_SPF = "v=spf1 include:new.example ~all";

  it("a value that merely CONTAINS v=spf1 (not at the start) is its own slot, so it is kept", () => {
    // Prevents: the `^` anchor being dropped and the leading `\s*` being widened
    // to `\S*` — either would let "v=spf1" be found mid-string and wrongly treat
    // an unrelated token as the SPF slot, deleting it when the real SPF is written.
    const out = unionHosts(
      [row("hello v=spf1 keepme"), row("zzv=spf1 keeptoo")] as never,
      [row(NEW_SPF, "@")] as never,
    ) as Row[];
    expect(addrs(out)).toContain("hello v=spf1 keepme");
    expect(addrs(out)).toContain("zzv=spf1 keeptoo");
    // Negative control: the real SPF is present.
    expect(addrs(out)).toContain(NEW_SPF);
  });

  it("a spaced 'v = spf1' / 'v= spf1' IS recognised as the SPF slot and collapses", () => {
    // Prevents: the `\s*` around `v`, `=` and after `=` being narrowed to `\S*`,
    // which would stop recognising whitespace-padded SPF tags and leave duplicate
    // v=spf1 records at the apex (an RFC 7208 permerror).
    const out = unionHosts(
      [row("v = spf1 include:a"), row("v= spf1 include:b")] as never,
      [row(NEW_SPF)] as never,
    ) as Row[];
    const spfLike = addrs(out).filter((a) => /^\s*"?\s*v\s*=\s*spf1/i.test(a));
    expect(spfLike).toEqual([NEW_SPF]);
  });

  it("the full tag distinguishes slots: DKIM and DMARC at one host do not displace each other", () => {
    // Prevents: the tag capture `+` being reduced to a single character (so
    // "v=dkim1" and "v=dmarc1" both collapse to "v=d"), the `v=${tag}` template
    // being blanked, and `tag[1] ?? ""` becoming `tag[1] && ""` (both collapse all
    // v= tags to one slot).
    const dkim = "v=DKIM1; p=MIGf...";
    const dmarc = "v=DMARC1; p=none";
    const out = unionHosts([row(dkim, "sel")] as never, [row(dmarc, "sel")] as never) as Row[];
    expect(addrs(out)).toContain(dkim);
    expect(addrs(out)).toContain(dmarc);
    expect(out).toHaveLength(2);
  });

  it("a non-tag value is slotted on its TRIMMED text, so a padded copy is deduped", () => {
    // Prevents: `address.trim()` being reduced to `address`, which would let
    // " token " and "token" occupy different slots and duplicate.
    const out = unionHosts(
      [row("  shared-token  ")] as never,
      [row("shared-token")] as never,
    ) as Row[];
    const matches = addrs(out).filter((a) => a.trim() === "shared-token");
    expect(matches).toEqual(["shared-token"]);
  });
});
