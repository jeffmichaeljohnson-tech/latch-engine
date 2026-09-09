# latch-engine

A DNS-automation engine: work out who hosts a domain's DNS, plan the records a
service needs, apply them through that provider's API, and verify they actually
resolved. Portable across Cloudflare Workers and Node, with zero runtime
dependencies.

## Shape

- **detect** — identify the DNS provider from nameservers, including
  Domain Connect discovery
- **records** — build and parse apex, MX, SPF, DKIM and DMARC records
- **providers** — Cloudflare, Route 53 (with its own SigV4 signer), Namecheap,
  and generic Domain Connect
- **connect** — turn a desired state into an ordered plan, and report coverage
- **verify** — check propagation, and schedule re-checks

## Test

```
npm install
npx vitest run
```

19 files, **212 tests**, **440 assertions**, all passing. Nothing is skipped and no assertion is vacuous.

The suite is **mutation-tested**, which is a stronger claim than a pass count.
Fifteen mutations were applied to real logic — DNS record type codes, the SPF
qualifier regex, DMARC tag ordering, TTL clamping, the MX duplicate-preference
check. Every one is caught.

Four of those mutations originally survived, all inside the DNSSEC detector. Its
four positive signals — the NS query's AD flag, the DS query's AD flag, a DS
answer, a DNSKEY answer — were exercised by a single test that fired two of them
at once and never reached the DNSKEY fallback at all, so any one branch could be
deleted with the suite still green. Each signal now has a test that isolates it.

The two numbers count different things: 208 is the number of `it()` blocks, 436
is the number of `expect()` calls inside them.

## Status

Extracted from a larger application. The DNS engine is the portable half; the
Worker, the brand assets and the marketing site are deliberately not part of this
repository.

MIT licensed.
