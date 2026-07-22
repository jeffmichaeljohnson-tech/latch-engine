import { afterEach, describe, expect, it, vi } from "vitest";
import {
  Route53Adapter,
  buildChangeBatchXml,
} from "../../src/providers/route53";
import { signRequest } from "../../src/providers/sigv4";
import type { DnsRecord } from "../../src/types";

const AUTH = {
  accessKeyId: "AKIAEXAMPLE",
  secretAccessKey: "secret-key",
  hostedZoneId: "/hostedzone/Z123ABC",
};

const CHANGE_INFO_OK = `<?xml version="1.0"?>
<ChangeResourceRecordSetsResponse><ChangeInfo><Id>/change/C1</Id><Status>PENDING</Status></ChangeInfo></ChangeResourceRecordSetsResponse>`;

// A fetch-shaped mock so `.mock.calls[n]` is typed as [url, init].
function fetchFn(impl: (input: string | URL, init?: RequestInit) => Promise<Response>) {
  return vi.fn(impl);
}

afterEach(() => vi.unstubAllGlobals());

describe("buildChangeBatchXml", () => {
  it("emits UPSERT change sets with FQDN names, TTL, and quoted TXT", () => {
    const records: DnsRecord[] = [
      { type: "A", host: "@", value: "1.2.3.4", ttl: 300, purpose: "site" },
      { type: "TXT", host: "@", value: "v=spf1 include:x ~all", ttl: 300, purpose: "spf" },
    ];
    const xml = buildChangeBatchXml("example.com", records);
    expect(xml).toContain("<Action>UPSERT</Action>");
    expect(xml).toContain("<Name>example.com.</Name>");
    expect(xml).toContain("<Type>A</Type>");
    expect(xml).toContain("<TTL>300</TTL>");
    expect(xml).toContain("<Value>1.2.3.4</Value>");
    // TXT value is wrapped in quotes (XML-escaped &quot;).
    expect(xml).toContain("&quot;v=spf1 include:x ~all&quot;");
  });

  it("groups records with the same name+type into ONE record set", () => {
    const records: DnsRecord[] = [
      { type: "MX", host: "@", value: "mx1.example.net", ttl: 3600, priority: 10, purpose: "mx" },
      { type: "MX", host: "@", value: "mx2.example.net", ttl: 3600, priority: 20, purpose: "mx" },
    ];
    const xml = buildChangeBatchXml("example.com", records);
    // Exactly one ResourceRecordSet, two ResourceRecords with priority prefixes.
    expect(xml.match(/<ResourceRecordSet>/g)).toHaveLength(1);
    expect(xml.match(/<ResourceRecord>/g)).toHaveLength(2);
    expect(xml).toContain("<Value>10 mx1.example.net</Value>");
    expect(xml).toContain("<Value>20 mx2.example.net</Value>");
  });

  it("builds an FQDN for a subdomain host", () => {
    const xml = buildChangeBatchXml("example.com", [
      { type: "CNAME", host: "mail", value: "ghs.example.net", ttl: 300 },
    ]);
    expect(xml).toContain("<Name>mail.example.com.</Name>");
  });
});

describe("SigV4 known-answer (AWS aws-sig-v4-test-suite: get-vanilla)", () => {
  it("produces the documented signature", async () => {
    const result = await signRequest({
      method: "GET",
      url: "https://example.amazonaws.com/",
      region: "us-east-1",
      service: "service",
      accessKeyId: "AKIDEXAMPLE",
      secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
      headers: { "x-amz-date": "20150830T123600Z" },
      amzDate: "20150830T123600Z",
      body: "",
    });
    expect(result.signedHeaders).toBe("host;x-amz-date");
    expect(result.signature).toBe(
      "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
    );
    expect(result.authorization).toBe(
      "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, " +
        "SignedHeaders=host;x-amz-date, " +
        "Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
    );
  });
});

describe("Route53Adapter.apply", () => {
  it("signs and POSTs the change batch, then reports applied", async () => {
    const fetchMock = fetchFn(async () => new Response(CHANGE_INFO_OK, { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    const records: DnsRecord[] = [
      { type: "A", host: "@", value: "1.2.3.4", ttl: 300 },
    ];
    const out = await new Route53Adapter().apply("example.com", records, AUTH);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe(
      "https://route53.amazonaws.com/2013-04-01/hostedzone/Z123ABC/rrset",
    );
    expect(init!.method).toBe("POST");
    const headers = init!.headers as Record<string, string>;
    expect(headers.authorization).toMatch(/^AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE\//);
    expect(headers["x-amz-date"]).toMatch(/^\d{8}T\d{6}Z$/);
    expect(init!.body).toContain("<Action>UPSERT</Action>");

    expect(out.applied).toHaveLength(1);
    expect(out.manual).toHaveLength(0);
  });

  it("throws provider_auth_failed on 403", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            "<ErrorResponse><Error><Code>AccessDenied</Code><Message>no</Message></Error></ErrorResponse>",
            { status: 403 },
          ),
      ),
    );
    await expect(
      new Route53Adapter().apply(
        "example.com",
        [{ type: "A", host: "@", value: "1.2.3.4", ttl: 300 }],
        AUTH,
      ),
    ).rejects.toMatchObject({ code: "provider_auth_failed" });
  });
});
