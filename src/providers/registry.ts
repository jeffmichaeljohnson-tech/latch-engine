// Latch — adapter registry.
//
// One place to look up a write adapter by its capability id. The orchestrator's
// detect() resolves a DetectMethod → an adapter id, then getAdapter(id) hands
// back the writer. Adapters are stateless singletons; per-call config (zone ids,
// creds) rides in AdapterAuth at apply() time.
//
// Exception: "domain-connect" needs per-detection config (providerId/serviceId/
// urlSyncUX) that has no place in Adapter.authUrl(). The registered instance is
// the unconfigured default (authUrl → null); build a configured one with
// makeDomainConnectAdapter() from detect() output.

import type { Adapter } from "../types";
import { cloudflareAdapter } from "./cloudflare";
import { domainConnectAdapter } from "./domain-connect";
import { namecheapAdapter } from "./namecheap";
import { route53Adapter } from "./route53";

const registry = new Map<string, Adapter>();

/** Register (or replace) an adapter under its capabilities().id. */
export function registerAdapter(adapter: Adapter): void {
  registry.set(adapter.capabilities().id, adapter);
}

/** Look up an adapter by id, or undefined if none is registered. */
export function getAdapter(id: string): Adapter | undefined {
  return registry.get(id);
}

/** All registered adapter ids. */
export function listAdapters(): string[] {
  return [...registry.keys()];
}

registerAdapter(cloudflareAdapter);
registerAdapter(domainConnectAdapter);
registerAdapter(namecheapAdapter);
registerAdapter(route53Adapter);
