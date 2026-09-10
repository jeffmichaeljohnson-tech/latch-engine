// Mutation-closing tests for src/net/resolver.ts.
// Focus: the numeric-RR-type map (the existing suite checks only 4 of its 10
// entries) and the escape handling in unquoteTxt (RFC 1035 §3.3.14 / §5.1).
import { describe, it, expect } from "vitest";
import { RR_TYPE, unquoteTxt } from "../../src/net/resolver";

describe("RR_TYPE — numeric RR code to name (the entries the existing suite omits)", () => {
  it("maps AAAA, CNAME, MX, NS, SOA and DS to their names", () => {
    // Prevents blanking any of these six map values.
    expect(RR_TYPE[28]).toBe("AAAA");
    expect(RR_TYPE[5]).toBe("CNAME");
    expect(RR_TYPE[15]).toBe("MX");
    expect(RR_TYPE[2]).toBe("NS");
    expect(RR_TYPE[6]).toBe("SOA");
    expect(RR_TYPE[43]).toBe("DS");
  });
});

describe("unquoteTxt — backslash escapes keep the escaped character", () => {
  it("decodes \\X to the literal X, not to nothing", () => {
    // Prevents `.replace(/\\(.)/g, "$1")` -> `.replace(/\\(.)/g, "")`, which would
    // delete the escaped character (RFC 1035 §5.1 character-string escaping).
    // Source datum: "a\;b"  ->  logical value a;b
    expect(unquoteTxt('"a\\;b"')).toBe("a;b");
  });
});
