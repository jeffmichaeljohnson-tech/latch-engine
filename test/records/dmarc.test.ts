import { describe, expect, it } from "vitest";
import { buildDmarc, mergeDmarc, parseDmarc, serializeDmarc } from "../../src/records/dmarc";

describe("dmarc: p=none default on a new record", () => {
  it("defaults to monitor-only p=none", () => {
    const { record, warnings } = buildDmarc();
    expect(record.host).toBe("_dmarc");
    expect(record.type).toBe("TXT");
    expect(record.value).toContain("v=DMARC1");
    expect(record.value).toContain("p=none");
    expect(warnings.map((w) => w.code)).not.toContain("existing_dmarc");
  });

  it("keeps v= first and p= second when tags are supplied", () => {
    const { record } = buildDmarc({ rua: "mailto:reports@example.com", pct: "100" });
    expect(record.value.startsWith("v=DMARC1; p=none;")).toBe(true);
    expect(record.value).toContain("rua=mailto:reports@example.com");
    expect(record.value).toContain("pct=100");
  });

  it("honors an explicit stricter policy when the caller sets it on a new record", () => {
    const { record } = buildDmarc({ p: "quarantine" });
    expect(record.value).toContain("p=quarantine");
  });
});

describe("dmarc: merge preserves existing tags, never clobbers", () => {
  it("keeps the existing p/rua/pct even when new tags differ", () => {
    const { record, warnings } = mergeDmarc({
      existingTxt: "v=DMARC1; p=reject; rua=mailto:old@example.com; pct=50",
      tags: { p: "none", rua: "mailto:new@example.com", ruf: "mailto:forensic@example.com" },
    });
    expect(record.value).toContain("p=reject"); // existing wins
    expect(record.value).toContain("rua=mailto:old@example.com"); // existing wins
    expect(record.value).toContain("pct=50"); // existing wins
    expect(record.value).toContain("ruf=mailto:forensic@example.com"); // gap filled by new tag
    expect(warnings.map((w) => w.code)).toContain("existing_dmarc");
  });

  it("does not treat a non-DMARC TXT as an existing record", () => {
    const { record, warnings } = mergeDmarc({
      existingTxt: "some-other-token=xyz",
      tags: { rua: "mailto:r@example.com" },
    });
    expect(record.value).toContain("p=none");
    expect(warnings.map((w) => w.code)).not.toContain("existing_dmarc");
  });

  it("round-trips through parse + serialize", () => {
    const tags = parseDmarc("v=DMARC1; p=none; rua=mailto:r@x.com");
    expect(tags).toEqual({ v: "DMARC1", p: "none", rua: "mailto:r@x.com" });
    expect(serializeDmarc(tags)).toBe("v=DMARC1; p=none; rua=mailto:r@x.com");
  });
});
