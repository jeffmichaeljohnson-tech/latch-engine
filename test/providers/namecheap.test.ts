import { afterEach, describe, expect, it, vi } from "vitest";
import { NamecheapAdapter, unionHosts } from "../../src/providers/namecheap";
import type { DnsRecord } from "../../src/types";

const AUTH = {
  apiUser: "gbuild",
  apiKey: "nc-secret",
  userName: "gbuild",
  clientIp: "203.0.113.7",
};

// An existing host set: apex A, www CNAME, and a live MX.
const GET_HOSTS_XML = `<?xml version="1.0" encoding="utf-8"?>
<ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response">
  <CommandResponse Type="namecheap.domains.dns.getHosts">
    <DomainDNSGetHostsResult Domain="example.com" IsUsingOurDNS="true">
      <host HostId="1" Name="@" Type="A" Address="1.2.3.4" MXPref="10" TTL="1800" />
      <host HostId="2" Name="www" Type="CNAME" Address="example.com." MXPref="10" TTL="1800" />
      <host HostId="3" Name="@" Type="MX" Address="mail.legacy.com." MXPref="10" TTL="1800" />
    </DomainDNSGetHostsResult>
  </CommandResponse>
</ApiResponse>`;

const SET_HOSTS_OK = `<?xml version="1.0" encoding="utf-8"?>
<ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response">
  <CommandResponse Type="namecheap.domains.dns.setHosts">
    <DomainDNSSetHostsResult Domain="example.com" IsSuccess="true" />
  </CommandResponse>
</ApiResponse>`;

afterEach(() => vi.unstubAllGlobals());

function parseSetHostsBody(body: string): Record<string, string> {
  return Object.fromEntries(new URLSearchParams(body));
}

describe("unionHosts", () => {
  it("replaces matching type+host and preserves everything unrelated", () => {
    const existing = [
      { name: "@", type: "A", address: "1.2.3.4", ttl: 1800 },
      { name: "www", type: "CNAME", address: "example.com.", ttl: 1800 },
      { name: "@", type: "MX", address: "mail.legacy.com.", mxPref: 10, ttl: 1800 },
    ];
    const incoming = [{ name: "@", type: "A", address: "9.9.9.9", ttl: 300 }];
    const merged = unionHosts(existing, incoming);

    // The apex A is replaced; www CNAME + apex MX are preserved.
    expect(merged).toHaveLength(3);
    const apexA = merged.find((r) => r.name === "@" && r.type === "A");
    expect(apexA!.address).toBe("9.9.9.9");
    expect(merged.some((r) => r.name === "www" && r.type === "CNAME")).toBe(true);
    expect(merged.some((r) => r.type === "MX" && r.address === "mail.legacy.com.")).toBe(true);
  });
});

describe("NamecheapAdapter.apply", () => {
  it("getHosts -> union -> setHosts preserves unrelated records", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response(GET_HOSTS_XML, { status: 200 }))
      .mockResolvedValueOnce(new Response(SET_HOSTS_OK, { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    // Add a new SPF TXT at the apex — must NOT clobber existing A/CNAME/MX.
    const record: DnsRecord = {
      type: "TXT",
      host: "@",
      value: "v=spf1 include:_spf.gbuild.app ~all",
      ttl: 1800,
      purpose: "spf",
    };
    const out = await new NamecheapAdapter().apply("example.com", [record], AUTH);

    expect(fetchMock).toHaveBeenCalledTimes(2);
    // getHosts first (GET, query string), setHosts second (POST body).
    expect(String(fetchMock.mock.calls[0]![0])).toContain("Command=namecheap.domains.dns.getHosts");

    const setInit = fetchMock.mock.calls[1]![1]!;
    expect(setInit.method).toBe("POST");
    const params = parseSetHostsBody(setInit.body as string);
    expect(params.Command).toBe("namecheap.domains.dns.setHosts");
    expect(params.SLD).toBe("example");
    expect(params.TLD).toBe("com");

    // 4 total hosts: existing A, CNAME, MX + the new TXT.
    const names = new Set<string>();
    const types = new Set<string>();
    for (let i = 1; params[`HostName${i}`]; i++) {
      names.add(params[`HostName${i}`]!);
      types.add(params[`RecordType${i}`]!);
    }
    expect(types).toContain("A");
    expect(types).toContain("CNAME");
    expect(types).toContain("MX");
    expect(types).toContain("TXT");

    // The MX must keep its MXPref.
    let mxIndex = -1;
    for (let i = 1; params[`RecordType${i}`]; i++) {
      if (params[`RecordType${i}`] === "MX") mxIndex = i;
    }
    expect(mxIndex).toBeGreaterThan(0);
    expect(params[`MXPref${mxIndex}`]).toBe("10");

    expect(out.applied).toHaveLength(1);
    expect(out.applied[0]!.type).toBe("TXT");
  });

  it("replaces a matching apex TXT rather than duplicating it", async () => {
    const existingWithSpf = GET_HOSTS_XML.replace(
      '<host HostId="3"',
      '<host HostId="9" Name="@" Type="TXT" Address="v=spf1 -all" MXPref="10" TTL="1800" />\n      <host HostId="3"',
    );
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response(existingWithSpf, { status: 200 }))
      .mockResolvedValueOnce(new Response(SET_HOSTS_OK, { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    const record: DnsRecord = {
      type: "TXT",
      host: "@",
      value: "v=spf1 include:_spf.gbuild.app ~all",
      ttl: 1800,
    };
    await new NamecheapAdapter().apply("example.com", [record], AUTH);

    const params = parseSetHostsBody(fetchMock.mock.calls[1]![1]!.body as string);
    let txtCount = 0;
    let txtValue = "";
    for (let i = 1; params[`RecordType${i}`]; i++) {
      if (params[`RecordType${i}`] === "TXT" && params[`HostName${i}`] === "@") {
        txtCount++;
        txtValue = params[`Address${i}`]!;
      }
    }
    expect(txtCount).toBe(1);
    expect(txtValue).toBe("v=spf1 include:_spf.gbuild.app ~all");
  });

  it("throws provider_rejected when setHosts returns an error", async () => {
    const errXml = `<ApiResponse Status="ERROR"><Errors><Error Number="2019166">Domain not found</Error></Errors></ApiResponse>`;
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response(GET_HOSTS_XML, { status: 200 }))
      .mockResolvedValueOnce(new Response(errXml, { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    const record: DnsRecord = { type: "A", host: "@", value: "9.9.9.9", ttl: 1800 };
    await expect(
      new NamecheapAdapter().apply("example.com", [record], AUTH),
    ).rejects.toMatchObject({ code: "provider_rejected" });
  });
});
