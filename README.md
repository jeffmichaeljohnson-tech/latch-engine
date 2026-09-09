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

21 files, **229 tests**, **465 assertions**, all passing. The two numbers count
different things: 229 `it()` blocks, and 465 `expect()` calls inside them. Nothing is skipped and no assertion is vacuous.

## Mutation

A pass count says a suite runs. It does not say the suite would notice if the
code were wrong. So the mutations are committed, not described:

```
npm run mutation
```

`mutations.json` lists twenty-three changes to real logic — DNS record type codes,
the SPF qualifier regex, DMARC tag ordering, TTL clamping, the MX
duplicate-preference check, every branch of the DNSSEC detector, both halves of
the multi-string TXT decoder, and the Cloudflare and Namecheap write paths. The
runner applies each one, runs the suite, restores the file and verifies the
restore by hash.

It reports four verdicts, and the third is why it exists:

| verdict | meaning |
|---|---|
| `KILLED` | the suite ran and failed — the mutation is caught |
| `SURVIVED` | the suite ran and passed — nothing pins this behaviour |
| `INCONCLUSIVE` | non-zero exit, but no evidence any test ran |
| `NOT-APPLIED` | the pattern was absent, or matched more than once |

A mutation that stops the code compiling also exits non-zero. A runner reading
only the exit code scores that as a kill it never earned, so a spec declares a
marker the test runner prints only when tests actually execute, and a non-zero
exit without it is `INCONCLUSIVE` — never counted as caught.

The runner has its own suite (`npm run test:mutation-runner`), because a tool
that measures test suites is a check, and a check nobody has watched fail is a
claim. It was driven red by reintroducing the exit-code-only defect.

Four of those mutations originally survived, all inside the DNSSEC detector. Its
four positive signals — the NS query's AD flag, the DS query's AD flag, a DS
answer, a DNSKEY answer — were exercised by a single test that fired two of them
at once and never reached the DNSKEY fallback at all, so any one branch could be
deleted with the suite still green. Each signal now has a test that isolates it.

## The writer created what the merge had just folded in

A red-team pass found the one that matters. `mergeSpf` reads the SPF already at
the apex, folds a new include into it and returns **one** record — and the
Cloudflare adapter then POSTed that merged record **beside** the original it had
merged from. Two `v=spf1` TXTs at the apex is an RFC 7208 permerror: all mail for
the domain fails. The call returned `status: "applied"`.

Route 53 had always UPSERTed and Namecheap unions its host list, so Cloudflare —
the only provider enabled by default — was the one that got it wrong, in the
module whose first six lines are about not breaking other people's mail.

The writer now reads the zone once, keys it by (type, name), and PUTs a match or
POSTs a miss. Three tests pin it: the update, the create, and a zone it could not
read — because falling back to a blind create there is the same bug one level
quieter. All three carry mutations.

## Status

Extracted from a larger application. The DNS engine is the portable half; the
Worker, the brand assets and the marketing site are deliberately not part of this
repository.

MIT licensed.
