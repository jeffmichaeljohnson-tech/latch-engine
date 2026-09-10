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

46 files, **817 tests**, **1,171 `expect()` call sites**, all passing. The two
numbers count different things and are not comparable: 817 is `it()` blocks,
1,171 is `expect()` calls in the source. There are fewer call sites than tests
because `it.each` runs one site many times — a fixture table of 37 nameservers is
one `expect()` and 37 tests. Nothing is skipped and no assertion is vacuous.

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

### The curated set is not a mutation score

Thirty-three of thirty-three is a perfect result against a list I wrote, which
proves that my imagination and my tests agree. They always do. The number below
is the one a reviewer gets:

```
npm i -D @stryker-mutator/core@^9 @stryker-mutator/vitest-runner@^9
npx stryker run
```

**3,135 generated mutants, 2,967 caught — 94.93%.** Stryker builds its own
mutants from the syntax tree rather than from a list, which is how the case
nobody thought to write down gets found.

| area | score |
|---|---|
| `detect/` | 96.46% — `ns-map.ts` at 100% |
| `verify/` | 97.32% — `status.ts` and `schedule.ts` at 100% |
| `net/` | 97.87% |
| `providers/` | 94.85% — `domain-connect.ts` and `registry.ts` at 100% |
| `records/` | 94.02% — `mx.ts` at 100% |
| `connect/` | 93.39% |

The first run of this scored **59.17%**, with 305 mutants in code no test
executed at all. Two examples of what that hid, both closed:

`ns-map.ts` — the provider table — scored **30.20%**. It was only ever reached
incidentally, by tests that happened to use two or three hostnames, so a mutant
could drop the `$` from the Route 53 pattern or delete Porkbun's second suffix
and every test stayed green. Eleven of its twenty-four entries had no fixture at
all. It is now 202 of 202.

The SPF all-term regex `/^[-~?+]?all$/i` had a purpose-written mutation test, and
three separate mutations of it still survived — dropping the `^`, dropping the
`$`, and making the qualifier required. All three survived for one reason: the
only fixture was `v=spf1 include:amazonses.com -all`, which none of them changes
the answer for. `include:_spf.recall allowme all` separates them. That took a
*second* pass over a file that already had a mutation test, which is the honest
argument for running a generator rather than trusting a list.

The lowest file is `sigv4.ts` at 86.49%, and it is named here rather than
averaged away. Its remaining survivors need values that can only be pinned from
this implementation, and the tests stop where the published AWS conformance
vector stops — a pin makes a change deliberate but cannot discover a bug, so the
line is drawn at what an external oracle can reach.

Around 60 mutants across the package are recorded in the test files as
**equivalent** — the mutated code cannot be told apart from the original by any
input — with the reasoning written beside each. Writing a test for one of those
would mean writing a test that passes either way, which is the defect this whole
exercise exists to remove.

A scheduled workflow re-runs the generator, so this table is measured rather than
remembered.

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
