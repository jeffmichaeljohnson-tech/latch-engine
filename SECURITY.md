# Security Policy

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository —
**Security → Advisories → Report a vulnerability**, or go straight to
[`../../security/advisories/new`](../../security/advisories/new). That channel is
private between you and the maintainer, and it is the only one that stays private.

**Please do not open a public issue for a suspected vulnerability.** If private
reporting is not available to you, open an issue saying only that you have a
security report and asking for a private channel. No details in the issue.

This project is maintained by one person, not a team with an on-call rotation. A
realistic expectation: acknowledgement within a week, an assessment within two.
If a report is valid, the fix and the advisory are published together, and you
are credited unless you ask not to be.

There is no bounty. Saying so plainly is more useful than leaving you to guess.

## Supported versions

The default branch is the only supported version. This project has not cut a
release series, so there is nothing to backport to.

## Threat model — read this before deciding whether you have a finding

This library detects which DNS provider hosts a domain and writes records
through that provider's API. It therefore handles **live credentials** and makes
**changes that affect where mail and traffic go**. Those two facts define the
surface.

**In scope.**

- **A credential reaching anywhere it should not.** Into a log line, an error
  message, a thrown exception's payload, a URL, a retry, or a request to a host
  other than the provider the credential belongs to. This is the most serious
  class here and the easiest to introduce by accident.
- **A record written to the wrong place.** The wrong zone, the wrong domain, or
  through the wrong provider's adapter — including any path where a value taken
  from a DNS answer or an API response influences which zone is targeted.
- **A signature that does not cover the request that is sent.** The AWS SigV4
  signer must sign the exact method, path, query, headers and body that go on
  the wire. A signature computed over anything else is a finding even if the
  request currently succeeds.
- **A plan that reports success without the change having been applied**, or
  reports a record as applied when the provider rejected or altered it. Callers
  act on that report.
- Any injection into a provider request through an attacker-influenced record
  name or value — header splitting, query smuggling, path traversal in an
  API path segment.

**Out of scope.**

- **Nameserver-based provider detection is spoofable by whoever controls the
  zone's NS records — and that is not a privilege boundary.** Anyone who can set
  a zone's nameservers already controls its DNS entirely. One entry is
  additionally infix rather than suffix-anchored, because AWS spreads its
  nameservers across four top-level domains; this is asserted by a test and
  written down rather than left to be discovered.
- The correctness or availability of a provider's own API.
- A provider that is not recognised. The map is explicitly non-exhaustive and
  falls through to a named-unknown manual path.
- Resource exhaustion from a hostile DNS answer.

**Standing properties.** The published package has no runtime dependencies. It
performs network requests only to the provider API selected for the domain and
to the DNS resolver it is given. It reads no environment variable of its own —
credentials are passed in by the caller.
