// Latch — v1 automated-write coverage policy.
//
// Which detected methods Latch actually drives automatically in v1. Anything not
// wired here degrades to the polished manual fallback (records table + verify poll)
// — never a dead end. Flipping a flag re-wires a method with no other code change.

import type { DetectMethod } from "../types";

export interface CoveragePolicy {
  /** Zones in OUR Cloudflare account (we own the API + the token). */
  cloudflare: boolean;
  /** Domain Connect sync flow (provider-mediated consent, no client secret). */
  domainConnect: boolean;
  /** AWS Route 53 via user-supplied scoped IAM creds (technical users). */
  route53: boolean;
  /** Namecheap. Authored but UNWIRED in v1: its API is IP-allowlisted + eligibility-
   *  gated on the end user's account and our Worker egress is a shared CF IP pool,
   *  so a single-domain novice is categorically ineligible. Routes to manual. */
  namecheap: boolean;
}

/**
 * v1 coverage (confirmed with JJ 2026-07-21): Cloudflare-owned + Route 53 fast-follow.
 * Namecheap → manual fallback.
 *
 * domainConnect is OFF until GBuild authors + registers the "gbuild-email" Domain
 * Connect template with the provider network — without that template the sync-apply
 * URL cannot apply, so advertising an automated DC flow would over-claim. The engine's
 * DC mechanism is fully built + tested; flip this to true once the template is live.
 */
export const V1_COVERAGE: CoveragePolicy = {
  cloudflare: true,
  domainConnect: false,
  route53: true,
  namecheap: false,
};

/** The adapter id embedded in an `adapter:<id>` method, or null. */
export function adapterIdOf(method: DetectMethod): string | null {
  return method.startsWith("adapter:") ? method.slice("adapter:".length) : null;
}

/** Is the detected method wired for automated handling under this policy? */
export function isWired(method: DetectMethod, policy: CoveragePolicy): boolean {
  if (method === "cloudflare") return policy.cloudflare;
  if (method === "domain_connect") return policy.domainConnect;
  if (method === "manual") return false;
  const id = adapterIdOf(method);
  if (id === "route53") return policy.route53;
  if (id === "namecheap") return policy.namecheap;
  return false;
}
