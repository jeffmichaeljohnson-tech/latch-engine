// Mutation-closing tests for src/verify/verify.ts.
// Never touches the network: a fake Resolver is injected everywhere, as the
// existing suite does. Each test names the defect it prevents. MX RDATA shape is
// RFC 1035 §3.3.9 (<preference> <exchange>).
import { describe, it, expect } from "vitest";
import {
  verifyOnce,
  pollUntil,
  responseMatches,
  toFqdn,
} from "../../src/verify/verify";
import { MAX_ELAPSED_MS } from "../../src/verify/schedule";
import type { Resolver, DnsResponse } from "../../src/net/resolver";
import type { DnsRecord } from "../../src/types";

const SPF: DnsRecord = {
  type: "TXT",
  host: "@",
  value: "v=spf1 include:_spf.google.com ~all",
  ttl: 300,
  purpose: "spf",
};

function txt(name: string, ...strings: string[]): DnsResponse {
  return {
    Status: 0,
    Answer: [{ name, type: 16, TTL: 300, data: strings.map((s) => `"${s}"`).join(" ") }],
  };
}

function fakeResolver(
  lookup: (name: string, type: string, endpoint: string) => DnsResponse | "throw",
): Resolver {
  return {
    async query(name, type, opts) {
      const r = lookup(name, type, opts?.endpoint ?? "default");
      if (r === "throw") throw new Error("DoH error");
      return r;
    },
  };
}

const TWO = ["cf", "goog"];

describe("toFqdn — name resolution edges", () => {
  it("trims and qualifies a padded bare label", () => {
    // Prevents dropping .trim().replace() on the host.
    expect(toFqdn(" mail ", "example.com")).toBe("mail.example.com");
  });

  it("returns the domain unchanged when the host already equals it", () => {
    // Prevents forcing the `h === domain || endsWith` branch false (which would
    // append the domain a second time).
    expect(toFqdn("example.com", "example.com")).toBe("example.com");
  });

  it("a sibling domain sharing the suffix but not a subdomain is re-qualified", () => {
    // Prevents `"." + domain` -> `"" + domain`: "notexample.com" is a DIFFERENT
    // registrable domain, not a subdomain of example.com, so it must be treated
    // as a label and qualified.
    expect(toFqdn("notexample.com", "example.com")).toBe("notexample.com.example.com");
  });
});

describe("responseMatches — value normalisation removes the trailing dot", () => {
  it("a CNAME answer with a trailing dot matches the dotless expected value", () => {
    // Prevents replacing normHost's body with the raw string: a DNS answer's
    // trailing dot must be normalised away before comparison.
    const rec: DnsRecord = { type: "CNAME", host: "www", value: "target.example.com", ttl: 300 };
    const resp: DnsResponse = {
      Status: 0,
      Answer: [{ name: "www.example.com", type: 5, TTL: 300, data: "target.example.com." }],
    };
    expect(responseMatches(resp, rec)).toBe(true);
  });
});

describe("responseMatches — the RR-type filter is load-bearing", () => {
  it("an answer whose DATA matches but whose TYPE is wrong is NOT a match", () => {
    // Prevents disabling the `a.type === rrType` filter (via returning the
    // unfiltered array or an always-true predicate): a TXT answer carrying
    // "1.2.3.4" must never satisfy an expected A record.
    const rec: DnsRecord = { type: "A", host: "@", value: "1.2.3.4", ttl: 300 };
    const resp: DnsResponse = {
      Status: 0,
      Answer: [{ name: "example.com", type: 16, TTL: 300, data: "1.2.3.4" }],
    };
    expect(responseMatches(resp, rec)).toBe(false);
  });

  it("our value counts as present even when other A records share the name", () => {
    // Prevents `answers.some(...)` -> `answers.every(...)`: a domain may hold
    // several A records; we confirm OUR value is among them.
    const rec: DnsRecord = { type: "A", host: "@", value: "1.2.3.4", ttl: 300 };
    const resp: DnsResponse = {
      Status: 0,
      Answer: [
        { name: "example.com", type: 1, TTL: 300, data: "1.2.3.4" },
        { name: "example.com", type: 1, TTL: 300, data: "5.6.7.8" },
      ],
    };
    expect(responseMatches(resp, rec)).toBe(true);
  });
});

describe("responseMatches — MX RDATA parsing (RFC 1035 §3.3.9)", () => {
  const mxRec: DnsRecord = {
    type: "MX",
    host: "@",
    value: "aspmx.l.google.com",
    ttl: 300,
    priority: 10,
    purpose: "mx",
  };

  it("a single-token MX answer (no preference) is malformed and cannot match", () => {
    // Prevents `if (parts.length < 2) return false` -> `return true`: an answer
    // lacking a preference must not spuriously confirm.
    const resp: DnsResponse = {
      Status: 0,
      Answer: [{ name: "example.com", type: 15, TTL: 300, data: "aspmx.l.google.com." }],
    };
    expect(responseMatches(resp, mxRec)).toBe(false);
  });

  it("MX RDATA is whitespace-tolerant: leading space in the datum still matches", () => {
    // Prevents dropping .trim() before the split (which would parse the empty
    // leading token as preference 0).
    const resp: DnsResponse = {
      Status: 0,
      Answer: [{ name: "example.com", type: 15, TTL: 300, data: " 10 aspmx.l.google.com." }],
    };
    expect(responseMatches(resp, mxRec)).toBe(true);
  });

  it("an expected MX with no preference matches any preference for that target", () => {
    // Prevents the `wantPrio === undefined ? true : ...` true-branch becoming
    // false: a preference-less expected record must match on target alone.
    const noPrio: DnsRecord = { type: "MX", host: "@", value: "aspmx.l.google.com", ttl: 300 };
    const resp: DnsResponse = {
      Status: 0,
      Answer: [{ name: "example.com", type: 15, TTL: 300, data: "20 aspmx.l.google.com." }],
    };
    expect(responseMatches(resp, noPrio)).toBe(true);
  });
});

describe("verifyOnce — authoritative signal + default endpoints", () => {
  it("a FUNCTION authoritative signal is invoked per record (not used truthily)", () => {
    // Prevents disabling / mis-typing the `typeof flag === "function"` branch: if
    // the function is not called, the truthy function object is passed on and the
    // record downgrades from the strong 'published' gate to 'confirmed'.
    const r = fakeResolver(() => txt("example.com", SPF.value)); // public confirms
    return verifyOnce("example.com", [SPF], r, {
      endpoints: TWO,
      authoritativeConfirmed: () => true,
    }).then((res) => {
      expect(res.records[0]?.status).toBe("published");
    });
  });

  it("uses the built-in default endpoints when none are passed", async () => {
    // Prevents emptying DEFAULT_ENDPOINTS: with [] no resolver is queried and the
    // record can never confirm.
    const r = fakeResolver(() => txt("example.com", SPF.value));
    const res = await verifyOnce("example.com", [SPF], r, {});
    expect(res.status).toBe("confirmed");
  });
});

describe("pollUntil — stamping and the elapsed clock", () => {
  it("does not attach a jobId key when none is supplied", async () => {
    // Prevents forcing the `jobId === undefined ? result : {...}` branch false,
    // which would add an explicit jobId:undefined key.
    let t = 0;
    const res = await pollUntil("example.com", [SPF], fakeResolver(() => txt("example.com", SPF.value)), {
      sleep: async (ms) => {
        t += ms;
      },
      now: () => t,
      endpoints: TWO,
    });
    expect(Object.prototype.hasOwnProperty.call(res, "jobId")).toBe(false);
  });

  it("elapsed is measured as now - start (a non-zero clock origin proves the sign)", async () => {
    // Prevents `deps.now() - start` -> `deps.now() + start`. With the clock
    // starting at the 72h cap, the correct elapsed on the first (pending) poll is
    // 0 (keep polling) but now+start = 2x the cap (give up immediately). So only
    // the correct '-' converges to 'confirmed'; the mutant returns 'failed'.
    let t = MAX_ELAPSED_MS;
    const start = t;
    const r = fakeResolver(() => (t > start ? txt("example.com", SPF.value) : { Status: 0 }));
    const res = await pollUntil("example.com", [SPF], r, {
      sleep: async (ms) => {
        t += ms;
      },
      now: () => t,
      endpoints: TWO,
    });
    expect(res.status).toBe("confirmed");
  });
});
