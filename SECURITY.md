# Security Policy

TIMPS-Parasol is a security product. We hold ourselves to the standard we're
asking you to trust: reports get a fast, honest response, and fixes ship
before we talk about them publicly.

## Supported versions

TIMPS-Parasol is currently in **research / developer preview** (`0.x`). Only
the latest published version on the `main` branch receives security fixes.

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ |
| < 0.1   | ❌ |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report privately using one of these channels:

- **GitHub Security Advisories** (preferred): open a draft advisory at
  `https://github.com/Sandeeprdy1729/timps-parasol/security/advisories/new`
- **Email**: timps.aio090@gmail.com — if that address bounces for you, reach
  the maintainer directly at the contact listed on
  [timps-website.vercel.app](https://timps-website.vercel.app/).

Please include:

- A description of the vulnerability and the layer/module it affects
  (Perimeter Gate, Identity & Trust, Data Vault, AI Safety Shield, Audit
  Sentinel, or one of the AgentChaos modules)
- Steps to reproduce, or a proof-of-concept scenario
- The impact you believe it has (what an attacker gains)
- Whether it's a bypass of an existing detector/gate, or a new attack class

If you found a prompt-injection, exfiltration, or containment bypass through
the benchmark harness (`npm run bench` / `npm run bench:holdout`), that's a
**finding, not necessarily a secret** — see the note at the end of this file.

## What to expect

- **Acknowledgment** within 3 business days.
- **Initial assessment** (severity, affected versions) within 7 business days.
- **Fix or mitigation timeline** communicated once triaged. Critical
  containment bypasses (anything that defeats the Universal Invariant —
  an unsigned actor forcing a restricted action through) are treated as
  highest priority.
- **Credit**: with your permission, we'll credit you in the release notes
  and CHANGELOG when the fix ships.

We ask that you give us a reasonable window to ship a fix before public
disclosure. We commit to not sitting on a real finding — our default is to
disclose once a fix is out, not to go quiet.

## Scope

In scope:

- The five core layers (`packages/core`, `packages/sdk`) and the six
  AgentChaos hardening modules (action gate, PII redactor, resource budget,
  identity anchor, social-pressure detector, intent-exfil classifier)
- The CLI (`cli/`) and API server (`api/`)
- Supply-chain issues in this repository (compromised dependency, malicious
  commit, leaked credential in history)

Out of scope (but still worth telling us about, just not under this policy):

- The dashboard (`dashboard/`) — currently a static/mock UI not wired to the
  SDK; see `docs/research-preview.md` for its status
- Denial-of-service via the benchmark/bench scripts themselves
- Vulnerabilities that require an attacker to already hold the owner's
  Ed25519 private key

## A note on benchmark "misses"

TIMPS-Parasol publishes its own gaps on purpose (see
[`docs/parasol-scorecard.md`](docs/parasol-scorecard.md) and the "What got
past us" section of the [intro blog](docs/blog-introducing-parasol.md)).
If you reproduce a documented residual (e.g. instruction-swap negation
evading the injection detector), you don't need to report it privately —
it's already tracked. If you find something **not** documented there, that's
a real report: please use the private channel above so we can harden it
before it's public.
