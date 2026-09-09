// setHosts has no per-record id: whatever is left out of the body is DELETED.
// TXT is the one type where several unrelated records legitimately share an owner
// name, so a union keyed on (type, host) alone deletes a stranger's verification
// token every time the SPF is written. These pin the narrowed key.
import { describe, it, expect } from "vitest";
import { unionHosts } from "../../src/providers/namecheap";

type Row = { name: string; type: string; address: string; ttl: number };
const row = (name: string, type: string, address: string, ttl = 1800): Row => ({
  name,
  type,
  address,
  ttl,
});
const addrs = (rows: Row[]) => rows.map((r) => r.address);

const GOOGLE = "google-site-verification=abc123";
const MS = "MS=ms12345678";
const OLD_SPF = "v=spf1 include:old.example ~all";
const NEW_SPF = "v=spf1 include:new.example ~all";

describe("Namecheap host union — the TXT slot", () => {
  it("writing the SPF keeps unrelated verification tokens at the SAME host", () => {
    const out = unionHosts(
      [row("@", "TXT", GOOGLE), row("@", "TXT", MS), row("@", "TXT", OLD_SPF)] as never,
      [row("@", "TXT", NEW_SPF, 300)] as never,
    ) as Row[];
    expect(addrs(out)).toContain(GOOGLE);
    expect(addrs(out)).toContain(MS);
  });

  it("writing the SPF REPLACES the old SPF — two v=spf1 at one name is a permerror", () => {
    const out = unionHosts(
      [row("@", "TXT", GOOGLE), row("@", "TXT", OLD_SPF)] as never,
      [row("@", "TXT", NEW_SPF, 300)] as never,
    ) as Row[];
    expect(addrs(out)).toContain(NEW_SPF);
    expect(addrs(out)).not.toContain(OLD_SPF);
    expect(addrs(out).filter((a) => /^v=spf1\b/i.test(a))).toHaveLength(1);
  });

  it("DMARC and SPF are different slots and do not displace each other", () => {
    const dmarc = "v=DMARC1; p=none; rua=mailto:x@example.com";
    const out = unionHosts(
      [row("_dmarc", "TXT", dmarc), row("@", "TXT", OLD_SPF)] as never,
      [row("@", "TXT", NEW_SPF, 300)] as never,
    ) as Row[];
    expect(addrs(out)).toContain(dmarc);
  });

  it("a v= tag is matched case-insensitively, so v=SPF1 is still the SPF slot", () => {
    const out = unionHosts(
      [row("@", "TXT", "V=SPF1 include:old.example ~all")] as never,
      [row("@", "TXT", NEW_SPF, 300)] as never,
    ) as Row[];
    expect(addrs(out).filter((a) => /^v=spf1\b/i.test(a))).toHaveLength(1);
  });

  it("rewriting an unrelated token with the SAME value is idempotent, not doubled", () => {
    const out = unionHosts(
      [row("@", "TXT", GOOGLE)] as never,
      [row("@", "TXT", GOOGLE, 300)] as never,
    ) as Row[];
    expect(addrs(out).filter((a) => a === GOOGLE)).toHaveLength(1);
  });

  it("non-TXT types are unchanged: an A write still replaces the A at that host", () => {
    const out = unionHosts(
      [row("@", "A", "1.2.3.4"), row("www", "CNAME", "example.com.")] as never,
      [row("@", "A", "5.6.7.8", 300)] as never,
    ) as Row[];
    expect(addrs(out)).toEqual(["example.com.", "5.6.7.8"]);
  });

  it("rows of an unrelated TYPE at the same host are always kept", () => {
    const out = unionHosts(
      [row("@", "MX", "mx.example.com"), row("@", "TXT", OLD_SPF)] as never,
      [row("@", "TXT", NEW_SPF, 300)] as never,
    ) as Row[];
    expect(addrs(out)).toContain("mx.example.com");
  });
});
