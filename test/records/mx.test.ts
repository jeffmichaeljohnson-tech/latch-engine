import { describe, expect, it } from "vitest";
import { buildMx } from "../../src/records/mx";
import { LatchError } from "../../src/types";

describe("mx: existing-MX clobber guard", () => {
  it("emits existing_mx naming the incumbent targets and still returns the desired records", () => {
    const { records, warnings } = buildMx({
      entries: [{ priority: 10, target: "aspmx.l.google.com" }],
      existingMx: ["mx1.incumbent.com", "mx2.incumbent.com"],
    });
    const warn = warnings.find((w) => w.code === "existing_mx");
    expect(warn).toBeDefined();
    expect(warn?.detail).toContain("mx1.incumbent.com");
    expect(warn?.detail).toContain("mx2.incumbent.com");
    expect(records.length).toBe(1); // not dropped — caller/UI hard-stops for confirm
  });

  it("emits no warning when there is no incumbent MX", () => {
    const { warnings } = buildMx({ entries: [{ priority: 10, target: "aspmx.l.google.com" }] });
    expect(warnings.map((w) => w.code)).not.toContain("existing_mx");
  });
});

describe("mx: unique priorities", () => {
  it("throws on duplicate priorities", () => {
    expect(() =>
      buildMx({
        entries: [
          { priority: 10, target: "a.example.com" },
          { priority: 10, target: "b.example.com" },
        ],
      }),
    ).toThrow(LatchError);
  });

  it("accepts distinct priorities", () => {
    const { records } = buildMx({
      entries: [
        { priority: 1, target: "aspmx.l.google.com" },
        { priority: 5, target: "alt1.aspmx.l.google.com" },
      ],
    });
    expect(records.map((r) => r.priority)).toEqual([1, 5]);
  });
});

describe("mx: FQDN trailing-dot normalization", () => {
  it("adds a trailing dot when missing", () => {
    const { records } = buildMx({ entries: [{ priority: 10, target: "aspmx.l.google.com" }] });
    expect(records[0]?.value).toBe("aspmx.l.google.com.");
  });

  it("does not double a trailing dot already present", () => {
    const { records } = buildMx({ entries: [{ priority: 10, target: "aspmx.l.google.com." }] });
    expect(records[0]?.value).toBe("aspmx.l.google.com.");
  });

  it("clamps the ttl to the 300 floor and defaults host to @", () => {
    const { records } = buildMx({ entries: [{ priority: 10, target: "mx.x.com" }], ttl: 30 });
    expect(records[0]?.ttl).toBe(300);
    expect(records[0]?.host).toBe("@");
    expect(records[0]?.purpose).toBe("mx");
  });
});

describe("mx: null-MX (RFC 7505)", () => {
  it("emits a single 0 . record and ignores entries", () => {
    const { records } = buildMx({
      entries: [{ priority: 10, target: "ignored.example.com" }],
      nullMx: true,
    });
    expect(records.length).toBe(1);
    expect(records[0]?.priority).toBe(0);
    expect(records[0]?.value).toBe(".");
  });
});
