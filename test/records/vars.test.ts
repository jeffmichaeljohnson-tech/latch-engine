import { describe, expect, it } from "vitest";
import {
  deriveVars,
  emailProviderSpfInclude,
  normalizeFqdn,
  resolveVars,
  splitSldTld,
} from "../../src/records/vars";
import type { DnsRecord, RecordVars } from "../../src/types";

describe("vars: dynamic variable resolution in host/value", () => {
  const vars: RecordVars = {
    DOMAIN: "example.com",
    SUBDOMAIN: "mail",
    SLD: "example",
    TLD: "com",
    emailProviderSPF: "include:_spf.google.com",
  };

  it("substitutes DOMAIN/SUBDOMAIN/SLD/TLD in host and value", () => {
    const rec: DnsRecord = {
      type: "CNAME",
      host: "{SUBDOMAIN}.{DOMAIN}",
      value: "{SLD}.{TLD}.cdn.net",
      ttl: 300,
    };
    const out = resolveVars(rec, vars);
    expect(out.host).toBe("mail.example.com");
    expect(out.value).toBe("example.com.cdn.net");
  });

  it("resolves emailProviderSPF inside an SPF value", () => {
    const rec: DnsRecord = { type: "TXT", host: "@", value: "v=spf1 {emailProviderSPF} ~all", ttl: 300 };
    expect(resolveVars(rec, vars).value).toBe("v=spf1 include:_spf.google.com ~all");
  });

  it("leaves an unset variable verbatim rather than emitting empty", () => {
    const partial: RecordVars = { DOMAIN: "example.com", SUBDOMAIN: "", SLD: "example", TLD: "com" };
    const rec: DnsRecord = { type: "TXT", host: "@", value: "{emailProviderSPF}", ttl: 300 };
    expect(resolveVars(rec, partial).value).toBe("{emailProviderSPF}");
  });
});

describe("vars: email provider -> SPF include map", () => {
  it("maps common providers (case-insensitive)", () => {
    expect(emailProviderSpfInclude("google")).toBe("include:_spf.google.com");
    expect(emailProviderSpfInclude("Microsoft")).toBe("include:spf.protection.outlook.com");
    expect(emailProviderSpfInclude("365")).toBe("include:spf.protection.outlook.com");
    expect(emailProviderSpfInclude("zoho")).toBe("include:zoho.com");
    expect(emailProviderSpfInclude("sendgrid")).toBe("include:sendgrid.net");
  });

  it("returns undefined for an unknown provider", () => {
    expect(emailProviderSpfInclude("nope-mail")).toBeUndefined();
  });
});

describe("vars: SLD/TLD split incl. multi-part public suffixes", () => {
  it("splits a plain two-label domain", () => {
    expect(splitSldTld("example.com")).toEqual({ sld: "example", tld: "com" });
  });

  it("splits a multi-part suffix (co.uk) correctly", () => {
    expect(splitSldTld("shop.co.uk")).toEqual({ sld: "shop", tld: "co.uk" });
  });

  it("splits com.au correctly", () => {
    expect(splitSldTld("acme.com.au")).toEqual({ sld: "acme", tld: "com.au" });
  });

  it("takes the registrable label under a deep subdomain on a multi-part suffix", () => {
    expect(splitSldTld("www.shop.co.uk")).toEqual({ sld: "shop", tld: "co.uk" });
  });

  it("KNOWN LIMITATION: a multi-part suffix not in the set mis-splits", () => {
    // gov.br is a real public suffix but not in our pragmatic set -> documented mis-split.
    expect(splitSldTld("agency.gov.br")).toEqual({ sld: "gov", tld: "br" });
  });
});

describe("vars: deriveVars + fqdn helper", () => {
  it("derives vars from a domain and resolves the email provider", () => {
    const v = deriveVars("shop.co.uk", { subdomain: "mail", emailProvider: "google" });
    expect(v).toEqual({
      DOMAIN: "shop.co.uk",
      SUBDOMAIN: "mail",
      SLD: "shop",
      TLD: "co.uk",
      emailProviderSPF: "include:_spf.google.com",
    });
  });

  it("normalizeFqdn adds a trailing dot and preserves the null-MX dot", () => {
    expect(normalizeFqdn("mx.example.com")).toBe("mx.example.com.");
    expect(normalizeFqdn("mx.example.com.")).toBe("mx.example.com.");
    expect(normalizeFqdn(".")).toBe(".");
  });
});
