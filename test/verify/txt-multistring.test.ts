// A TXT value over 255 octets is published as several quoted character-strings
// that DNS concatenates back into one logical value (RFC 1035 3.3.14). Every
// 2048-bit DKIM key is one. These tests pin that the EXPECTED side and the ANSWER
// side are decoded identically -- they were not, and a correctly published key
// verified as absent forever.
import { describe, it, expect } from "vitest";
import { buildDkim, TXT_STRING_LIMIT } from "../../src/records/dkim";
import { responseMatches } from "../../src/verify/verify";
import { unquoteTxt } from "../../src/net/resolver";
import type { DnsRecord } from "../../src/types";

/** ~392 base64 chars is a real 2048-bit p=; well over the 255-octet limit. */
const KEY_2048 = "v=DKIM1; k=rsa; p=" + "A".repeat(392);

function txtAnswer(name: string, data: string) {
  return { Status: 0, Answer: [{ name, type: 16, TTL: 300, data }] };
}

describe("multi-string TXT verification", () => {
  it("a 2048-bit DKIM key is chunked into more than one character-string", () => {
    const { record } = buildDkim({ selector: "s1", recordType: "TXT", value: KEY_2048 });
    expect(KEY_2048.length).toBeGreaterThan(TXT_STRING_LIMIT);
    expect(record.value).toContain('" "');
  });

  it("the chunked key the engine WROTE is the key it RECOGNISES", () => {
    const { record } = buildDkim({ selector: "s1", recordType: "TXT", value: KEY_2048 });
    // A resolver renders the multi-string TXT exactly as the record was written.
    expect(responseMatches(txtAnswer("s1._domainkey.example.com", record.value) as never, record)).toBe(true);
  });

  it("both sides decode to the SAME logical value, which is the original key", () => {
    const { record } = buildDkim({ selector: "s1", recordType: "TXT", value: KEY_2048 });
    expect(unquoteTxt(record.value)).toBe(KEY_2048);
  });

  it("a DIFFERENT chunked key at the same selector is NOT a match", () => {
    const { record } = buildDkim({ selector: "s1", recordType: "TXT", value: KEY_2048 });
    const other = buildDkim({
      selector: "s1",
      recordType: "TXT",
      value: "v=DKIM1; k=rsa; p=" + "B".repeat(392),
    }).record;
    expect(responseMatches(txtAnswer("s1._domainkey.example.com", other.value) as never, record)).toBe(false);
  });

  it("a key differing in ONE character inside the SECOND chunk is not a match", () => {
    // Guards against a decoder that compares only the first character-string.
    const tail = "A".repeat(391) + "Z";
    const record = buildDkim({ selector: "s1", recordType: "TXT", value: KEY_2048 }).record;
    const near = buildDkim({ selector: "s1", recordType: "TXT", value: "v=DKIM1; k=rsa; p=" + tail }).record;
    expect(responseMatches(txtAnswer("s1._domainkey.example.com", near.value) as never, record)).toBe(false);
  });

  it("control: a SHORT, unchunked TXT still verifies", () => {
    const short: DnsRecord = { type: "TXT", host: "@", value: "v=spf1 include:example.com ~all", ttl: 300 };
    expect(responseMatches(txtAnswer("example.com", `"${short.value}"`) as never, short)).toBe(true);
  });

  it("control: an unquoted answer datum still verifies", () => {
    const short: DnsRecord = { type: "TXT", host: "@", value: "v=spf1 -all", ttl: 300 };
    expect(responseMatches(txtAnswer("example.com", "v=spf1 -all") as never, short)).toBe(true);
  });
});
