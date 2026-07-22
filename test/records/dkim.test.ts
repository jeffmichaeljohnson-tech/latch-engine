import { describe, expect, it } from "vitest";
import { buildDkim, dkimHost, formatTxtValue, splitTxtString } from "../../src/records/dkim";
import { LatchError } from "../../src/types";

describe("dkim: CNAME vs TXT is an input, never guessed", () => {
  it("builds a CNAME when the provider specifies CNAME (Resend/SES style)", () => {
    const { record } = buildDkim({
      selector: "resend",
      recordType: "CNAME",
      value: "abc.dkim.amazonses.com",
    });
    expect(record.type).toBe("CNAME");
    expect(record.host).toBe("resend._domainkey");
    expect(record.value).toBe("abc.dkim.amazonses.com");
    expect(record.purpose).toBe("dkim");
  });

  it("builds a TXT when the provider specifies TXT (SendGrid/Google style)", () => {
    const { record } = buildDkim({
      selector: "google",
      recordType: "TXT",
      value: "v=DKIM1; k=rsa; p=SHORTKEY",
    });
    expect(record.type).toBe("TXT");
    expect(record.host).toBe("google._domainkey");
    expect(record.value).toBe("v=DKIM1; k=rsa; p=SHORTKEY");
  });
});

describe("dkim: 255-octet split into ONE record with multiple quoted strings", () => {
  const longKey = "v=DKIM1; k=rsa; p=" + "A".repeat(500);

  it("splitTxtString chunks at 255 and reassembles to the original", () => {
    const parts = splitTxtString(longKey);
    expect(parts.length).toBeGreaterThan(1);
    for (const p of parts) expect(p.length).toBeLessThanOrEqual(255);
    expect(parts.join("")).toBe(longKey);
  });

  it("formatTxtValue emits space-separated quoted strings for a long key", () => {
    const v = formatTxtValue(longKey);
    const quoted = v.match(/"[^"]*"/g) ?? [];
    expect(quoted.length).toBeGreaterThan(1);
    // one logical record: joining the unquoted pieces restores the key
    expect(quoted.map((q) => q.slice(1, -1)).join("")).toBe(longKey);
  });

  it("a short key stays a single unquoted verbatim string", () => {
    expect(formatTxtValue("v=DKIM1; p=short")).toBe("v=DKIM1; p=short");
  });

  it("buildDkim produces exactly ONE record even for an over-length key", () => {
    const { record } = buildDkim({ selector: "s1", recordType: "TXT", value: longKey });
    expect(record.type).toBe("TXT");
    expect((record.value.match(/"[^"]*"/g) ?? []).length).toBeGreaterThan(1);
  });
});

describe("dkim: one-record-type-per-selector-label guard (RFC 1034)", () => {
  it("refuses a CNAME when the label already holds a TXT", () => {
    expect(() =>
      buildDkim({
        selector: "s1",
        recordType: "CNAME",
        value: "x.dkim.example.com",
        existingTypesAtLabel: ["TXT"],
      }),
    ).toThrow(LatchError);
  });

  it("refuses a TXT when the label already holds a CNAME", () => {
    expect(() =>
      buildDkim({
        selector: "s1",
        recordType: "TXT",
        value: "v=DKIM1; p=x",
        existingTypesAtLabel: ["CNAME"],
      }),
    ).toThrow(LatchError);
  });

  it("allows a CNAME when the label already holds only a CNAME (idempotent replace)", () => {
    expect(() =>
      buildDkim({
        selector: "s1",
        recordType: "CNAME",
        value: "x.dkim.example.com",
        existingTypesAtLabel: ["CNAME"],
      }),
    ).not.toThrow();
  });

  it("dkimHost composes <selector>._domainkey", () => {
    expect(dkimHost("s1")).toBe("s1._domainkey");
  });
});
