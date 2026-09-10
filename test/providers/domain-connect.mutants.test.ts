// Mutation-closing tests for src/providers/domain-connect.ts.
// The existing suite covers the happy-path URL and encoding; these pin the
// optional-param branches, trailing-slash normalisation, and the capabilities
// surface that a caller relies on to decide the write path.
import { describe, expect, it } from "vitest";
import {
  DomainConnectAdapter,
  makeDomainConnectAdapter,
} from "../../src/providers/domain-connect";

const base = {
  providerId: "GoDaddy",
  serviceId: "gbuild-email",
  urlSyncUX: "https://domainconnect.godaddy.com/sync",
};

describe("DomainConnectAdapter.authUrl — optional params", () => {
  it("sets groupId to its actual value only when supplied", async () => {
    // Prevents blanking the groupId value and prevents forcing the guard false.
    const url = await makeDomainConnectAdapter({ ...base, groupId: "grp-7" }).authUrl(
      "example.com",
      "gbuild://cb",
    );
    expect(new URL(url as string).searchParams.get("groupId")).toBe("grp-7");
  });

  it("omits groupId entirely when it is not supplied", async () => {
    // Prevents forcing the groupId guard true (which would set "undefined").
    const url = await makeDomainConnectAdapter(base).authUrl("example.com", "gbuild://cb");
    expect(new URL(url as string).searchParams.has("groupId")).toBe(false);
  });

  it("omits state entirely when it is not supplied", async () => {
    // Prevents forcing the state guard true (which would set "undefined").
    const url = await makeDomainConnectAdapter(base).authUrl("example.com", "gbuild://cb");
    expect(new URL(url as string).searchParams.has("state")).toBe(false);
  });

  it("strips ALL trailing slashes from the sync-UX base, not just one", async () => {
    // Prevents `/\/+$/` -> `/\/$/`: multiple trailing slashes would leave a
    // doubled slash in the path.
    const url = await makeDomainConnectAdapter({
      ...base,
      urlSyncUX: "https://domainconnect.godaddy.com/sync///",
    }).authUrl("example.com", "gbuild://cb");
    expect(new URL(url as string).pathname).toBe(
      "/sync/v2/domainTemplates/providers/GoDaddy/services/gbuild-email/apply",
    );
  });
});

describe("DomainConnectAdapter.capabilities — surface a caller branches on", () => {
  it("advertises the exact writable record types, display name, and apex support", () => {
    // Prevents emptying DEFAULT_WRITES / blanking any of its elements, blanking the
    // displayName, and flipping supportsApex to false.
    const caps = new DomainConnectAdapter().capabilities();
    expect(caps.writesRecordTypes).toEqual(["A", "AAAA", "CNAME", "MX", "TXT"]);
    expect(caps.displayName).toBe("Domain Connect");
    expect(caps.supportsApex).toBe(true);
  });
});
