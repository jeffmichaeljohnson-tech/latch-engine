import { describe, expect, it } from "vitest";
import type { DnsRecord } from "../../src/types";
import { planEmailRecords, planSiteRecords } from "../../src/connect/plan";

const findByPurpose = (rs: DnsRecord[], p: string) => rs.filter((r) => r.purpose === p);

describe("planEmailRecords", () => {
  it("hosts the identity on a subdomain by default (avoids the apex MX clobber)", () => {
    const { records } = planEmailRecords(
      { subdomain: "agent", spfIncludes: ["include:_spf.resend.com"] },
      [],
    );
    const spf = findByPurpose(records, "spf")[0]!;
    expect(spf.host).toBe("agent");
    expect(spf.value).toContain("include:_spf.resend.com");
    const dmarc = findByPurpose(records, "dmarc")[0]!;
    expect(dmarc.host).toBe("_dmarc.agent");
    expect(dmarc.value).toContain("p=none");
  });

  it("merges into an existing SPF at the SAME host, never a second v=spf1", () => {
    const existing: DnsRecord[] = [
      { type: "TXT", host: "agent", value: "v=spf1 include:_spf.google.com ~all", ttl: 3600 },
    ];
    const { records, warnings } = planEmailRecords(
      { subdomain: "agent", spfIncludes: ["include:_spf.resend.com"] },
      existing,
    );
    const spf = findByPurpose(records, "spf")[0]!;
    expect(spf.value).toBe("v=spf1 include:_spf.google.com include:_spf.resend.com ~all");
    expect(warnings.some((w) => w.code === "existing_spf")).toBe(true);
  });

  it("does NOT merge an apex SPF into a subdomain identity (different host)", () => {
    const existing: DnsRecord[] = [
      { type: "TXT", host: "@", value: "v=spf1 include:_spf.google.com -all", ttl: 3600 },
    ];
    const { records } = planEmailRecords(
      { subdomain: "agent", spfIncludes: ["include:_spf.resend.com"] },
      existing,
    );
    const spf = findByPurpose(records, "spf")[0]!;
    expect(spf.value).not.toContain("_spf.google.com");
    expect(spf.value).toContain("_spf.resend.com");
  });

  it("warns existing_mx only when writing MX where a live provider already receives mail", () => {
    const apexMx: DnsRecord[] = [
      { type: "MX", host: "@", value: "aspmx.l.google.com.", ttl: 3600, priority: 1 },
    ];
    // Subdomain identity: apex MX is untouched → no clobber warning.
    const sub = planEmailRecords(
      { subdomain: "agent", spfIncludes: [], mx: [{ priority: 10, target: "mx.resend.com" }] },
      apexMx,
    );
    expect(sub.warnings.some((w) => w.code === "existing_mx")).toBe(false);
    // Apex identity with the same existing MX → clobber warning fires.
    const apex = planEmailRecords(
      { subdomain: "", spfIncludes: [], mx: [{ priority: 10, target: "mx.resend.com" }] },
      apexMx,
    );
    expect(apex.warnings.some((w) => w.code === "existing_mx")).toBe(true);
  });

  it("places a DKIM record at <selector>._domainkey under the subdomain", () => {
    const { records } = planEmailRecords(
      {
        subdomain: "agent",
        spfIncludes: [],
        dkim: [{ selector: "resend", recordType: "CNAME", value: "resend._domainkey.resend.com." }],
      },
      [],
    );
    const dkim = findByPurpose(records, "dkim")[0]!;
    expect(dkim.host).toBe("resend._domainkey.agent");
    expect(dkim.type).toBe("CNAME");
  });

  it("omits MX entirely for a send-only identity", () => {
    const { records } = planEmailRecords({ subdomain: "agent", spfIncludes: [] }, []);
    expect(findByPurpose(records, "mx")).toHaveLength(0);
  });
});

describe("planSiteRecords", () => {
  it("subdomain → a plain CNAME to the target", () => {
    const { records } = planSiteRecords(
      { subdomain: "www", target: "pages.gbuild.app", supportsApex: false },
      [],
    );
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({ type: "CNAME", host: "www", value: "pages.gbuild.app." });
  });

  it("apex on a flattening host → a CNAME at @", () => {
    const { records } = planSiteRecords(
      { subdomain: "", target: "pages.gbuild.app", supportsApex: true },
      [],
    );
    expect(records[0]).toMatchObject({ type: "CNAME", host: "@" });
  });

  it("apex on a non-flattening host with resolved IPs → A/AAAA (never a literal apex CNAME)", () => {
    const { records } = planSiteRecords(
      { subdomain: "", target: "pages.gbuild.app", supportsApex: false, resolved: { a: ["1.2.3.4"] } },
      [],
    );
    expect(records.every((r) => r.type !== "CNAME")).toBe(true);
    expect(records[0]).toMatchObject({ type: "A", host: "@", value: "1.2.3.4" });
  });

  it("apex, non-flattening, unresolved → warns and writes nothing (caller resolves first)", () => {
    const { records, warnings } = planSiteRecords(
      { subdomain: "", target: "pages.gbuild.app", supportsApex: false },
      [],
    );
    expect(records).toHaveLength(0);
    expect(warnings.some((w) => w.code === "apex_cname")).toBe(true);
  });
});
