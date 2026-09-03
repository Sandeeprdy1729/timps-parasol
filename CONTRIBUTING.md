# Contributing to TIMPS-Parasol

Thanks for considering a contribution. This is a research/developer preview
of a security product — the bar for changes here is a bit different from a
typical app repo, so please read this before opening a PR.

## Before you start

For anything beyond a typo fix, open an issue first describing what you want
to change and why. This avoids wasted work on both sides, especially for
anything touching a detection surface (injection, exfiltration, action
gating) where a "fix" that isn't measured against the benchmark can quietly
regress detection rates.

## Development setup

```bash
git clone https://github.com/Sandeeprdy1729/timps-parasol.git
cd timps-parasol
npm install
npm run build
npm test
```

Requires Node.js ≥ 20.

## Project layout

```
packages/core   shared types, constants, errors, utilities
packages/sdk    the five security layers + AgentChaos modules + benchmarks
cli/            command-line interface
api/            Fastify API server
dashboard/      React dashboard (static/mock — not wired to the SDK yet)
docs/           architecture, reference docs, blog, benchmark scorecard
```

## Making changes

1. Fork the repo and create a branch off `main`.
2. Write or update tests in `packages/sdk/tests/` for any behavioral change.
   The adversarial suite is the thing that makes our benchmark numbers
   trustworthy — a PR that touches a detector without a test is unlikely to
   be merged.
3. Run the full check before opening a PR:
   ```bash
   npm run build
   npm test
   npm run lint
   ```
4. If your change affects a benchmarked surface (injection detection,
   PII redaction, action gating, resource budgets, identity, social-pressure
   detection), regenerate the numbers and include the delta in your PR
   description:
   ```bash
   npm run bench
   npm run bench:holdout
   ```
   A PR that improves dev-set detection but regresses the hold-out score is
   a strong signal of overfitting — see `docs/parasol-scorecard.md` for how
   we read that.
5. Keep commits scoped and messages descriptive. We don't require a specific
   commit format, but "fix bug" is not a description.

## Reporting a security issue

**Do not open a public issue for a vulnerability or a containment bypass
that isn't already documented in `docs/parasol-scorecard.md`.** See
[SECURITY.md](SECURITY.md) for the private reporting process.

If you found a bypass that's already listed as a known residual (e.g. the
instruction-swap negation gap), a public issue or PR is fine — it's already
tracked, and a fix is welcome.

## What we're looking for right now

Check the roadmap in [`docs/blog-introducing-parasol.md`](docs/blog-introducing-parasol.md):

- Agent Coordination Shield (covert agent-to-agent channel detection)
- Full-revocation kill switch
- Credential & infrastructure guard
- Durable persistence for audit/containment state

Contributions toward closing the documented hold-out gap (obfuscation
resistance in the injection detector) are especially welcome — bring a
benchmark delta, not just a claim.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By
participating, you're expected to uphold it.

## License

By contributing, you agree that your contributions will be licensed under
the [Apache License 2.0](LICENSE), the same license as the rest of the
project.
