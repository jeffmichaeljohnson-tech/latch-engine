// Mutation-closing tests for src/records/dmarc.ts.
// Each test names the DEFECT it prevents; DMARC rules are asserted against
// RFC 7489 where they are fixed by the spec (marked RFC).
import { describe, expect, it } from "vitest";
import { mergeDmarc, parseDmarc, serializeDmarc } from "../../src/records/dmarc";

describe("dmarc.isDmarc — the v=DMARC1 recogniser is anchored + trimmed", () => {
  it("does NOT treat a TXT that only embeds v=DMARC1 mid-string as an existing DMARC", () => {
    // Prevents dropping the ^ anchor. RFC 7489 §6.3: the v tag MUST be first, so
    // "junk v=DMARC1..." is not a DMARC record and its p=reject must not be adopted.
    const { record, warnings } = mergeDmarc({
      existingTxt: "notdmarc v=DMARC1; p=reject",
    });
    expect(record.value).toContain("p=none"); // fresh default, existing not honoured
    expect(warnings.map((w) => w.code)).not.toContain("existing_dmarc");
  });

  it("recognises an existing record that carries leading whitespace", () => {
    // Prevents dropping .trim() before the anchor test.
    const { record, warnings } = mergeDmarc({ existingTxt: " v=DMARC1; p=reject" });
    expect(warnings.map((w) => w.code)).toContain("existing_dmarc");
    expect(record.value).toContain("p=reject"); // existing preserved
  });
});

describe("dmarc.parseDmarc — tag extraction", () => {
  it("ignores a segment that has no '=' (not a tag)", () => {
    // Prevents disabling the eq === -1 guard: a bare word is not a tag=value pair
    // (RFC 7489 §6.4) and must not become a bogus key.
    expect(parseDmarc("v=DMARC1; garbage; p=none")).toEqual({
      v: "DMARC1",
      p: "none",
    });
  });

  it("trims whitespace around both key and value", () => {
    // Prevents dropping .trim() on either the key slice or the value slice.
    expect(parseDmarc("v = DMARC1 ; p = quarantine ; adkim = r")).toEqual({
      v: "DMARC1",
      p: "quarantine",
      adkim: "r",
    });
  });

  it("drops a segment whose key is empty (e.g. a leading '=value')", () => {
    // Prevents forcing the `k !== ""` guard true / changing its literal: an empty
    // key must never be written into the tag map.
    expect(parseDmarc("v=DMARC1; =orphan")).toEqual({ v: "DMARC1" });
  });
});

describe("dmarc.serializeDmarc — canonical tag ordering (RFC 7489 §6.4 v first)", () => {
  it("emits every known tag in the fixed order regardless of insertion order", () => {
    // Prevents emptying/[]-ing TAG_ORDER, disabling either serialize loop, and
    // blanking any single order element. Input is in REVERSE order on purpose so
    // any dropped ordering surfaces as a wrong string.
    const scrambled = {
      ri: "86400",
      rf: "afrf",
      fo: "1",
      aspf: "r",
      adkim: "r",
      pct: "100",
      ruf: "mailto:f@example.com",
      rua: "mailto:a@example.com",
      sp: "none",
      p: "none",
      v: "DMARC1",
    };
    expect(serializeDmarc(scrambled)).toBe(
      "v=DMARC1; p=none; sp=none; rua=mailto:a@example.com; ruf=mailto:f@example.com; " +
        "pct=100; adkim=r; aspf=r; fo=1; rf=afrf; ri=86400",
    );
  });

  it("appends an unknown tag after the ordered ones (does not drop it)", () => {
    // Prevents disabling the second (unknown-tag) loop / blanking its pushed value.
    const out = serializeDmarc({ v: "DMARC1", p: "none", foo: "bar" });
    expect(out).toContain("foo=bar");
    expect(out.startsWith("v=DMARC1; p=none")).toBe(true);
  });
});

describe("dmarc.mergeDmarc — the existing_dmarc warning", () => {
  it("quotes the existing (trimmed) policy in the warning detail", () => {
    // Prevents blanking the detail template and prevents dropping .trim() on it.
    const { warnings } = mergeDmarc({ existingTxt: " v=DMARC1; p=reject " });
    const warn = warnings.find((w) => w.code === "existing_dmarc");
    expect(warn?.detail).toContain("v=DMARC1; p=reject");
    expect(warn?.detail.endsWith("reject")).toBe(true); // trimmed, no trailing space
  });
});
