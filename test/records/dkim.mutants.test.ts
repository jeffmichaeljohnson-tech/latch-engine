// Mutation-closing tests for src/records/dkim.ts.
// Each test names the DEFECT it prevents. The 255-octet character-string rule is
// RFC 1035 §3.3.14; the CNAME-coexistence rule is RFC 1034 §3.6.2.
import { describe, expect, it } from "vitest";
import {
  buildDkim,
  dkimHost,
  formatTxtValue,
  splitTxtString,
} from "../../src/records/dkim";
import { LatchError } from "../../src/types";

describe("dkim.unquote (via formatTxtValue) — strips exactly one surrounding pair", () => {
  it("unwraps a pre-quoted value to its content, not to empty", () => {
    // Prevents `m[1] ?? ""` -> `m[1] && ""`, which would blank every quoted value.
    expect(formatTxtValue('"v=DKIM1; p=short"')).toBe("v=DKIM1; p=short");
  });

  it("trims an unquoted value (the no-match branch)", () => {
    // Prevents dropping .trim() from the else branch.
    expect(formatTxtValue("  v=DKIM1; p=short  ")).toBe("v=DKIM1; p=short");
  });

  it("only unwraps when the quote is at both the start AND the end", () => {
    // Prevents dropping the ^ or the $ from the unquote regex: a value that is not
    // fully wrapped must be left verbatim (only trimmed).
    expect(formatTxtValue('prefix"abc"')).toBe('prefix"abc"');
    expect(formatTxtValue('"abc"suffix')).toBe('"abc"suffix');
  });

  it("unwraps multi-character content including spaces (regex class is [\\s\\S]*)", () => {
    // Prevents [\s\S]->[\s\S single], [^\s\S], [\S\S] and [\s\s] regex mutants:
    // the content between the quotes may be many chars, incl. whitespace.
    expect(formatTxtValue('"a b c"')).toBe("a b c");
    expect(formatTxtValue('"abc"')).toBe("abc");
  });

  it("trims before matching so an outer-padded quoted value still unwraps", () => {
    // Prevents dropping .trim() inside .exec(value.trim()).
    expect(formatTxtValue('  "abc"  ')).toBe("abc");
  });
});

describe("dkim.splitTxtString — RFC 1035 §3.3.14 255-octet chunking", () => {
  it("returns a single empty chunk for an empty value (never an empty array)", () => {
    // Prevents disabling the `raw.length <= limit` early return: the chunk loop
    // would produce [] for "", losing the one logical (empty) string.
    expect(splitTxtString("")).toEqual([""]);
  });

  it("does not append a trailing empty chunk when length is a multiple of the limit", () => {
    // Prevents `i < raw.length` -> `i <= raw.length`, which emits a stray "" chunk
    // at the exact boundary. 510 = 2 * 255.
    const parts = splitTxtString("A".repeat(510), 255);
    expect(parts).toHaveLength(2);
    expect(parts.every((p) => p.length === 255)).toBe(true);
  });
});

describe("dkim.dkimHost", () => {
  it("trims the selector before composing the owner name", () => {
    // Prevents dropping .trim() on the selector.
    expect(dkimHost("  resend  ")).toBe("resend._domainkey");
  });
});

describe("dkim.buildDkim — CNAME coexistence (RFC 1034 §3.6.2) + value handling", () => {
  it("allows a CNAME when no conflicting record type exists at the label", () => {
    // Prevents forcing the CNAME-guard condition to always throw.
    expect(() =>
      buildDkim({ selector: "s1", recordType: "CNAME", value: "x.dkim.example.com" }),
    ).not.toThrow();
  });

  it("refusing a CNAME beside another type throws unsupported and cites RFC 1034", () => {
    // Prevents blanking the LatchError code and the message.
    let err: unknown;
    try {
      buildDkim({
        selector: "s1",
        recordType: "CNAME",
        value: "x.dkim.example.com",
        existingTypesAtLabel: ["TXT"],
      });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(LatchError);
    expect((err as LatchError).code).toBe("unsupported");
    expect((err as LatchError).message).toContain("RFC 1034");
    expect((err as LatchError).message).toContain("s1._domainkey");
  });

  it("refusing a TXT beside a CNAME throws unsupported and cites RFC 1034", () => {
    // Prevents blanking the second throw's code and message.
    let err: unknown;
    try {
      buildDkim({
        selector: "s1",
        recordType: "TXT",
        value: "v=DKIM1; p=x",
        existingTypesAtLabel: ["CNAME"],
      });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(LatchError);
    expect((err as LatchError).code).toBe("unsupported");
    expect((err as LatchError).message).toContain("RFC 1034");
  });

  it("a CNAME value is trimmed but NOT quote-stripped (only TXT is chunk-formatted)", () => {
    // Prevents forcing the record-type ternary always-true (which would route a
    // CNAME through formatTxtValue and unwrap its quotes) and prevents dropping
    // .trim() on the CNAME branch.
    expect(
      buildDkim({ selector: "s", recordType: "CNAME", value: " abc.example.com " }).record
        .value,
    ).toBe("abc.example.com");
    expect(
      buildDkim({ selector: "s", recordType: "CNAME", value: '"abc.example.com"' }).record
        .value,
    ).toBe('"abc.example.com"');
  });
});
