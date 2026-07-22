import { describe, it, expect } from "vitest";
import {
  verifyOnce,
  pollUntil,
  responseMatches,
  toFqdn,
  type PollDeps,
} from "../../src/verify/verify";
import { MAX_ELAPSED_MS } from "../../src/verify/schedule";
import type { Resolver, DnsResponse } from "../../src/net/resolver";
import type { DnsRecord } from "../../src/types";

// ---------------------------------------------------------------------------
// DoH response builders (mirror the wire shape the real resolver returns)
// ---------------------------------------------------------------------------

const NONE: DnsResponse = { Status: 0 };

/** One TXT record; `strings` become one answer's quoted chunks (RFC 1035 multi-string). */
function txt(name: string, ...strings: string[]): DnsResponse {
  const data = strings.map((s) => `"${s}"`).join(" ");
  return { Status: 0, Answer: [{ name, type: 16, TTL: 300, data }] };
}

function mx(name: string, prio: number, target: string): DnsResponse {
  return { Status: 0, Answer: [{ name, type: 15, TTL: 300, data: `${prio} ${target}` }] };
}

function cname(name: string, target: string): DnsResponse {
  return { Status: 0, Answer: [{ name, type: 5, TTL: 300, data: target }] };
}

function a(name: string, ip: string): DnsResponse {
  return { Status: 0, Answer: [{ name, type: 1, TTL: 300, data: ip }] };
}

/** Build a fake resolver from a per-(name,type,endpoint) canned lookup. "throw" → hard error. */
function fakeResolver(
  lookup: (name: string, type: string, endpoint: string) => DnsResponse | "throw",
): Resolver {
  return {
    async query(name, type, opts) {
      const r = lookup(name, type, opts?.endpoint ?? "default");
      if (r === "throw") throw new Error("DoH boom");
      return r;
    },
  };
}

const CF = "cf";
const GOOG = "goog";
const TWO = [CF, GOOG];

/** Injected clock: sleep advances `now`. */
function fakeClock() {
  let t = 0;
  const sleep = async (ms: number): Promise<void> => {
    t += ms;
  };
  const now = (): number => t;
  return { sleep, now, at: () => t };
}

// ---------------------------------------------------------------------------
// toFqdn
// ---------------------------------------------------------------------------

describe("toFqdn", () => {
  it("apex → domain", () => {
    expect(toFqdn("@", "example.com")).toBe("example.com");
    expect(toFqdn("", "example.com")).toBe("example.com");
  });
  it("label → label.domain", () => {
    expect(toFqdn("mail", "example.com")).toBe("mail.example.com");
    expect(toFqdn("_dmarc", "example.com")).toBe("_dmarc.example.com");
  });
  it("already-FQDN is left alone (minus trailing dot)", () => {
    expect(toFqdn("mail.example.com", "example.com")).toBe("mail.example.com");
    expect(toFqdn("mail.example.com.", "example.com")).toBe("mail.example.com");
  });
});

// ---------------------------------------------------------------------------
// responseMatches — per-type compare
// ---------------------------------------------------------------------------

describe("responseMatches — TXT", () => {
  const spf: DnsRecord = {
    type: "TXT",
    host: "@",
    value: "v=spf1 include:_spf.google.com ~all",
    ttl: 300,
    purpose: "spf",
  };

  it("matches a single-string TXT", () => {
    expect(responseMatches(txt("example.com", spf.value), spf)).toBe(true);
  });

  it("matches a multi-string TXT (concatenated logical value)", () => {
    const dkim: DnsRecord = {
      type: "TXT",
      host: "sel._domainkey",
      value: "v=DKIM1;k=rsa;p=AAAABBBBCCCCDDDD",
      ttl: 300,
      purpose: "dkim",
    };
    // Split across two quoted chunks in one record — must be joined before compare.
    const resp = txt("sel._domainkey.example.com", "v=DKIM1;k=rsa;p=AAAABBBB", "CCCCDDDD");
    expect(responseMatches(resp, dkim)).toBe(true);
  });

  it("does not match a different TXT value", () => {
    expect(responseMatches(txt("example.com", "v=spf1 -all"), spf)).toBe(false);
  });

  it("no answer → no match", () => {
    expect(responseMatches(NONE, spf)).toBe(false);
  });
});

describe("responseMatches — MX", () => {
  const rec: DnsRecord = {
    type: "MX",
    host: "@",
    value: "aspmx.l.google.com",
    ttl: 300,
    priority: 10,
    purpose: "mx",
  };

  it("matches target + priority (trailing dot / case tolerant)", () => {
    expect(responseMatches(mx("example.com", 10, "ASPMX.L.GOOGLE.COM."), rec)).toBe(true);
  });

  it("wrong priority → no match", () => {
    expect(responseMatches(mx("example.com", 20, "aspmx.l.google.com."), rec)).toBe(false);
  });

  it("wrong target → no match", () => {
    expect(responseMatches(mx("example.com", 10, "mail.other.com."), rec)).toBe(false);
  });
});

describe("responseMatches — CNAME / A", () => {
  it("CNAME target matches (dot/case tolerant)", () => {
    const rec: DnsRecord = { type: "CNAME", host: "www", value: "cname.gbuild.app", ttl: 300 };
    expect(responseMatches(cname("www.example.com", "CNAME.GBUILD.APP."), rec)).toBe(true);
  });

  it("A value matches", () => {
    const rec: DnsRecord = { type: "A", host: "@", value: "192.0.2.10", ttl: 300 };
    expect(responseMatches(a("example.com", "192.0.2.10"), rec)).toBe(true);
    expect(responseMatches(a("example.com", "192.0.2.11"), rec)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// verifyOnce
// ---------------------------------------------------------------------------

const SPF: DnsRecord = {
  type: "TXT",
  host: "@",
  value: "v=spf1 include:_spf.google.com ~all",
  ttl: 300,
  purpose: "spf",
};

describe("verifyOnce", () => {
  it("all resolvers confirm → published", async () => {
    const r = fakeResolver(() => txt("example.com", SPF.value));
    const res = await verifyOnce("example.com", [SPF], r, { endpoints: TWO });
    expect(res.status).toBe("published");
    expect(res.records).toHaveLength(1);
    expect(res.records[0]?.status).toBe("published");
    expect(res.domain).toBe("example.com");
  });

  it("split (one resolver confirms, the other stale) → propagating", async () => {
    const r = fakeResolver((_n, _t, endpoint) =>
      endpoint === CF ? txt("example.com", SPF.value) : NONE,
    );
    const res = await verifyOnce("example.com", [SPF], r, { endpoints: TWO });
    expect(res.status).toBe("propagating");
    expect(res.records[0]?.status).toBe("propagating");
  });

  it("no resolver confirms → pending", async () => {
    const r = fakeResolver(() => NONE);
    const res = await verifyOnce("example.com", [SPF], r, { endpoints: TWO });
    expect(res.status).toBe("pending");
    expect(res.records[0]?.status).toBe("pending");
  });

  it("all resolvers hard-error → failed", async () => {
    const r = fakeResolver(() => "throw");
    const res = await verifyOnce("example.com", [SPF], r, { endpoints: TWO });
    expect(res.status).toBe("failed");
    expect(res.records[0]?.status).toBe("failed");
  });

  it("authoritative read-back wins over stale public resolvers → propagating", async () => {
    const r = fakeResolver(() => NONE); // public is blind
    const res = await verifyOnce("example.com", [SPF], r, {
      endpoints: TWO,
      authoritativeConfirmed: true,
    });
    expect(res.records[0]?.status).toBe("propagating");
  });

  it("authoritative confirm + public caught up → published", async () => {
    const r = fakeResolver(() => txt("example.com", SPF.value));
    const res = await verifyOnce("example.com", [SPF], r, {
      endpoints: TWO,
      authoritativeConfirmed: true,
    });
    expect(res.records[0]?.status).toBe("published");
  });

  it("rolls up multiple records (one published, one pending → propagating)", async () => {
    const mxRec: DnsRecord = {
      type: "MX",
      host: "@",
      value: "aspmx.l.google.com",
      ttl: 300,
      priority: 10,
      purpose: "mx",
    };
    const r = fakeResolver((_n, type) =>
      type === "TXT" ? txt("example.com", SPF.value) : NONE,
    );
    const res = await verifyOnce("example.com", [SPF, mxRec], r, { endpoints: TWO });
    expect(res.status).toBe("propagating");
    expect(res.records.map((x) => x.status)).toEqual(["published", "pending"]);
  });
});

// ---------------------------------------------------------------------------
// pollUntil
// ---------------------------------------------------------------------------

describe("pollUntil", () => {
  const deps = (over: Partial<PollDeps>): PollDeps => {
    const c = fakeClock();
    return { sleep: c.sleep, now: c.now, endpoints: TWO, ...over };
  };

  it("returns immediately when already published (no sleep needed)", async () => {
    const clock = fakeClock();
    const r = fakeResolver(() => txt("example.com", SPF.value));
    const res = await pollUntil("example.com", [SPF], r, {
      sleep: clock.sleep,
      now: clock.now,
      endpoints: TWO,
    });
    expect(res.status).toBe("published");
    expect(clock.at()).toBe(0); // never slept
  });

  it("converges to published after propagation delay", async () => {
    const clock = fakeClock();
    // Cloudflare always sees it; Google only after 30s of elapsed (propagation lag).
    const r = fakeResolver((_n, _t, endpoint) => {
      if (endpoint === CF) return txt("example.com", SPF.value);
      return clock.at() >= 30_000 ? txt("example.com", SPF.value) : NONE;
    });
    const res = await pollUntil("example.com", [SPF], r, {
      sleep: clock.sleep,
      now: clock.now,
      endpoints: TWO,
    });
    expect(res.status).toBe("published");
    expect(clock.at()).toBeGreaterThanOrEqual(30_000);
    expect(clock.at()).toBeLessThan(60_000); // caught in the fast (10s) phase
  });

  it("stamps jobId on the result", async () => {
    const clock = fakeClock();
    const r = fakeResolver(() => txt("example.com", SPF.value));
    const res = await pollUntil("example.com", [SPF], r, {
      sleep: clock.sleep,
      now: clock.now,
      endpoints: TWO,
      jobId: "job-123",
    });
    expect(res.jobId).toBe("job-123");
  });

  it("returns failed immediately on a hard error", async () => {
    const clock = fakeClock();
    const r = fakeResolver(() => "throw");
    const res = await pollUntil("example.com", [SPF], r, {
      sleep: clock.sleep,
      now: clock.now,
      endpoints: TWO,
    });
    expect(res.status).toBe("failed");
    expect(clock.at()).toBe(0);
  });

  it("gives up at the 72h cap → failed", async () => {
    const clock = fakeClock();
    const r = fakeResolver(() => NONE); // never confirms
    const res = await pollUntil("example.com", [SPF], r, {
      sleep: clock.sleep,
      now: clock.now,
      endpoints: TWO,
    });
    expect(res.status).toBe("failed");
    expect(clock.at()).toBeGreaterThanOrEqual(MAX_ELAPSED_MS);
  });

  it("uses deps helper shape without error", async () => {
    const r = fakeResolver(() => txt("example.com", SPF.value));
    const res = await pollUntil("example.com", [SPF], r, deps({}));
    expect(res.status).toBe("published");
  });
});
