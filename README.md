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

## Use

Identify who hosts a zone's DNS from its nameservers, then plan the records a
send-only email identity needs — merge-safe against whatever is already at the
zone. Both calls below are pure and synchronous: no network, no credentials.

```ts
import { matchNameservers, planEmailRecords } from "latch-engine";

// Who hosts this zone's DNS? (matched on the authoritative NS suffix)
const host = matchNameservers(["aida.ns.cloudflare.com", "rick.ns.cloudflare.com"]);
// → { id: "cloudflare", displayName: "Cloudflare", treatment: "cloudflare" }

// Plan the DNS a send-only identity needs, under a subdomain so the apex MX is
// left intact. The second argument is the records already present at the zone.
const { records, warnings } = planEmailRecords(
  {
    subdomain: "send",
    spfIncludes: ["include:_spf.resend.com"],
    dmarcTags: { p: "none" }, // monitor-only to start
  },
  [], // no existing records
);

for (const r of records) console.log(r.type, r.host, r.value);
// TXT send         v=spf1 include:_spf.resend.com ~all
// TXT _dmarc.send  v=DMARC1; p=none
```

**This package ships TypeScript source, not a build.** `exports` points at
`src/index.ts`, so the snippet above runs under a TypeScript-aware runtime or
bundler — `tsx`, `vitest`, Vite, esbuild, Bun, Deno — and **not** under plain
`node`, which will report `ERR_MODULE_NOT_FOUND`. That is deliberate: the engine
targets both Cloudflare Workers and Node, has zero runtime dependencies, and
shipping source lets each host compile it the way it already compiles everything
else, instead of shipping a build that suits neither. Verified as a consumer
would see it: `npm install latch-engine && npx tsx example.ts` prints
`{"id":"cloudflare","displayName":"Cloudflare","treatment":"cloudflare"}`.

Applying `records` through a provider — the Cloudflare, Route 53, Namecheap or
Domain Connect adapter — and verifying they resolved is the `providers` and
`verify` half of the surface; `src/index.ts` is the full export barrel.

## Test

```
npm install
npx vitest run
```

24 files, **248 tests**, **496 assertions**, all passing. The two numbers count
different things: 248 `it()` blocks, and 496 `expect()` calls inside them. Nothing is skipped and no assertion is vacuous.

## Mutation

A pass count says a suite runs. It does not say the suite would notice if the
code were wrong. So the mutations are committed, not described:

```
npm run mutation
```

`mutations.json` lists thirty-three changes to real logic — DNS record type codes,
the SPF qualifier regex, DMARC tag ordering, TTL clamping, the MX
duplicate-preference check, every branch of the DNSSEC detector, both halves of
the multi-string TXT decoder, the DoH request's DNSSEC flag and its non-ok error
path, the nameserver normaliser, the Route 53 SigV4 signer, and the Cloudflare
and Namecheap write paths. The runner applies each one, runs the suite, restores
the file and verifies the restore by hash.

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
