import { describe, it, expect } from "vitest";
import {
  discoverDomainConnect,
  settingsUrl,
  type SettingsFetcher,
} from "../../src/detect/domain-connect";
import type { Resolver, DnsResponse, DnsQueryType, QueryOptions } from "../../src/net/resolver";

// Mutation-closing tests for src/detect/domain-connect.ts (the DISCOVERY module).
//
// NOTE: this is the detect-side discovery, not src/providers/domain-connect.ts —
// that adapter has its own test/providers/domain-connect.mutants.test.ts and is
// not touched here.
//
// The existing test/detect/detect.test.ts covers the happy path and three
// failure modes (no TXT, no endpoint, settings-fetch throws). This file pins the
// parts a mutation run left open: settingsUrl's trimming, scheme detection, and
// trailing-slash normalization; the TXT selection (trim + first-non-empty); and
// the two "never throws" catch/guard paths that a fetch failure or a null
// settings body must land on. No network — the resolver and fetcher are fakes.

// --- Fake resolver: answers only the _domainconnect TXT lookup discovery makes. ---

const RR_TXT = 16;

class TxtResolver implements Resolver {
  constructor(
    private readonly answers: string[],
    private readonly shouldThrow = false,
  ) {}

  async query(name: string, _type: DnsQueryType, _opts?: QueryOptions): Promise<DnsResponse> {
    if (this.shouldThrow) throw new Error("simulated TXT lookup failure");
    return {
      Status: 0,
      Answer: this.answers.map((v) => ({ name, type: RR_TXT, TTL: 3600, data: `"${v}"` })),
    };
  }
}

const okSettings: SettingsFetcher = async () => ({
  providerId: "GoDaddy",
  urlSyncUX: "https://domainconnect.godaddy.com/sync",
});

// ---------------------------------------------------------------------------
// settingsUrl()
// ---------------------------------------------------------------------------

describe("settingsUrl(): normalization of the TXT-advertised host", () => {
  it("trims surrounding whitespace on the advertised value", () => {
    // Prevents dropping txtValue.trim() (L55 MethodExpression): a padded TXT value
    // would otherwise fold its spaces into the host portion of the URL.
    expect(settingsUrl("  domainconnect.godaddy.com  ", "shop.com")).toBe(
      "https://domainconnect.godaddy.com/v2/shop.com/settings",
    );
  });

  it("prefixes https:// to a bare host and does NOT accept a scheme embedded mid-value", () => {
    // Prevents removing the `^` anchor from /^https?:\/\//i (L56 Regex). A bare
    // host that merely CONTAINS "://" somewhere is still a bare host: the anchored
    // test treats it as such and prefixes https://. An unanchored test would read
    // it as an absolute URL and skip the prefix. Negative control against a
    // malformed advertisement.
    expect(settingsUrl("host-embeds-https://elsewhere", "d.com")).toBe(
      "https://host-embeds-https://elsewhere/v2/d.com/settings",
    );
  });

  it("preserves an explicit http:// scheme rather than double-prefixing it", () => {
    // Prevents dropping the `?` from /^https?:\/\//i (L56 Regex). Without the
    // optional "s", a plain-http advertisement no longer matches and gets a bogus
    // "https://http://…" prefix. A provider is allowed to advertise plain http.
    expect(settingsUrl("http://dc.example.com", "d.com")).toBe(
      "http://dc.example.com/v2/d.com/settings",
    );
  });

  it("strips ALL trailing slashes from the advertised value, not just one", () => {
    // Prevents narrowing /\/+$/ to /\/$/ (L57 Regex): several trailing slashes
    // would otherwise leave a doubled slash in the path.
    expect(settingsUrl("https://dc.example.com///", "d.com")).toBe(
      "https://dc.example.com/v2/d.com/settings",
    );
  });
});

// ---------------------------------------------------------------------------
// discoverDomainConnect() — TXT value selection
// ---------------------------------------------------------------------------

describe("discoverDomainConnect(): choosing the advertised host from TXT", () => {
  it("treats a whitespace-only TXT value as no host (unsupported)", async () => {
    // Prevents dropping the .map(v => v.trim()) before .find (L78 MethodExpression):
    // a value of only spaces trims to "" and must be rejected. Without the trim it
    // would pass the length check, become a "host", and drive a spurious fetch.
    // The fetcher below WOULD say supported, so a false result proves the trim held.
    const out = await discoverDomainConnect("ws.com", new TxtResolver(["   "]), okSettings);
    expect(out.supported).toBe(false);
  });

  it("skips an empty TXT value and uses the first non-empty one", async () => {
    // Prevents forcing the find predicate true (L78 ConditionalExpression) or
    // widening `> 0` to `>= 0` (L78 EqualityOperator): either would pick the empty
    // first value, yield an empty host, and report unsupported. The real code must
    // skip past "" to the usable host and confirm support.
    const out = await discoverDomainConnect(
      "pick.com",
      new TxtResolver(["", "dc.real.com"]),
      okSettings,
    );
    expect(out.supported).toBe(true);
    expect(out.urlSyncUX).toBe("https://domainconnect.godaddy.com/sync");
  });
});

// ---------------------------------------------------------------------------
// discoverDomainConnect() — the two "never throws" boundaries
// ---------------------------------------------------------------------------

describe("discoverDomainConnect(): failures resolve to unsupported, never throw", () => {
  it("a TXT-lookup failure resolves to unsupported", async () => {
    // Pins the TXT-query catch (L74 BlockStatement): an emptied catch would leave
    // txtValues unassigned and the next line would throw on undefined.map. The
    // documented contract is that discovery NEVER throws.
    const out = await discoverDomainConnect(
      "boom.com",
      new TxtResolver([], /* shouldThrow */ true),
      okSettings,
    );
    expect(out.supported).toBe(false);
  });

  it("a null settings body resolves to unsupported without dereferencing it", async () => {
    // Prevents dropping the `if (!settings)` guard (L87 ConditionalExpression):
    // reading settings.urlSyncUX on a null body (this check sits outside the
    // try/catch) would throw. A fetcher that returns null must yield unsupported.
    const nullFetch: SettingsFetcher = async () => null;
    const out = await discoverDomainConnect(
      "empty.com",
      new TxtResolver(["dc.empty.com"]),
      nullFetch,
    );
    expect(out.supported).toBe(false);
  });
});
