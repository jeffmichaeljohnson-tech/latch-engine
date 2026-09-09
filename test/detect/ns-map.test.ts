// ns-map is the fallback identity layer: before live Domain Connect discovery
// runs, this is what names the DNS host and picks the write path. Two behaviours
// carry weight and had no direct test. normalizeNs decides whether a real
// nameserver string ("NS1.Cloudflare.com." off a registrar API, trailing dot and
// all) matches at all. And matchNameservers scans the WHOLE nameserver set, not
// just the first entry, so a delegation whose first NS is unrecognised still
// resolves on a later one. The treatment/adapterId/parking fields are what the
// orchestrator branches on, so they are pinned to their host too.
import { describe, it, expect } from "vitest";
import { matchNameservers, normalizeNs } from "../../src/detect/ns-map";

describe("normalizeNs()", () => {
  it("lowercases, strips a single trailing dot, and trims surrounding space", () => {
    expect(normalizeNs("  NS1.Cloudflare.COM.  ")).toBe("ns1.cloudflare.com");
  });
  it("leaves an already-normal hostname unchanged", () => {
    expect(normalizeNs("dns1.registrar-servers.com")).toBe(
      "dns1.registrar-servers.com",
    );
  });
});

describe("matchNameservers()", () => {
  it("returns null for an empty nameserver set", () => {
    expect(matchNameservers([])).toBeNull();
  });

  it("matches on a LATER nameserver when the first is unrecognised", () => {
    const id = matchNameservers([
      "ns1.some-unknown-host.tld",
      "aida.ns.cloudflare.com",
    ]);
    expect(id?.id).toBe("cloudflare");
  });

  it("carries the adapter treatment and adapterId for Route 53", () => {
    const id = matchNameservers(["ns-1234.awsdns-56.org"]);
    expect(id?.treatment).toBe("adapter");
    expect(id?.adapterId).toBe("route53");
  });

  it("flags a parking service as parking, not as a writable host", () => {
    const id = matchNameservers(["ns1.sedoparking.com"]);
    expect(id?.parking).toBe(true);
    expect(id?.treatment).toBe("manual");
  });

  it("marks GoDaddy as a Domain Connect host", () => {
    const id = matchNameservers(["ns01.domaincontrol.com"]);
    expect(id?.treatment).toBe("domain_connect");
    expect(id?.domainConnectLikely).toBe(true);
  });
});
