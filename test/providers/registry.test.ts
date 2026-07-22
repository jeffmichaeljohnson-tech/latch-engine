import { describe, expect, it } from "vitest";
import {
  getAdapter,
  listAdapters,
  registerAdapter,
} from "../../src/providers/registry";
import type { Adapter, AdapterCapabilities } from "../../src/types";

describe("adapter registry", () => {
  it("registers the four adapters keyed by capability id", () => {
    const ids = listAdapters();
    expect(ids).toContain("cloudflare");
    expect(ids).toContain("domain-connect");
    expect(ids).toContain("namecheap");
    expect(ids).toContain("route53");
  });

  it("getAdapter returns the adapter whose capabilities().id matches", () => {
    expect(getAdapter("cloudflare")!.capabilities().id).toBe("cloudflare");
    expect(getAdapter("route53")!.capabilities().authKind).toBe("iam");
    expect(getAdapter("namecheap")!.capabilities().authKind).toBe("api_key");
    expect(getAdapter("domain-connect")!.capabilities().authKind).toBe(
      "domain_connect_sync",
    );
  });

  it("returns undefined for an unknown id", () => {
    expect(getAdapter("nope")).toBeUndefined();
  });

  it("registerAdapter replaces by id", () => {
    const fake: Adapter = {
      capabilities(): AdapterCapabilities {
        return {
          id: "test-fake",
          displayName: "Fake",
          automated: false,
          authKind: "none",
          writesRecordTypes: ["A"],
          supportsApex: false,
        };
      },
      async apply() {
        return { applied: [], manual: [] };
      },
    };
    registerAdapter(fake);
    expect(getAdapter("test-fake")).toBe(fake);
  });
});
