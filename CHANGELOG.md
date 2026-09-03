# Changelog

All notable changes to this project are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased] — public preview readiness

### Added
- `LICENSE` (Apache-2.0) at the repository root.
- `SECURITY.md` — private vulnerability disclosure process.
- `CONTRIBUTING.md` — dev setup, PR expectations, benchmark-delta requirement for detector changes.
- `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1).
- `@timps/parasol-core` shared foundation package (types, constants, errors, utilities).
- Embedding-tier injection detector (`embedding-injection.ts`) and intent-based exfiltration classifier (`intent-exfil.ts`).
- Risk-scored irreversible-action gate (HARD_BLOCK / CONFIRM / SAFE) replacing keyword-only matching.
- Out-of-sample hold-out benchmark harness (`bench:holdout`) and companion charts.
- `docs/blog-introducing-parasol.md`, `docs/research-preview.md`, `docs/parasol-scorecard.md`.
- `license`, `repository`, `homepage`, `bugs`, `author`, `description`, and `keywords` fields across all workspace `package.json` files.

### Changed
- All benchmark and architecture diagrams (`docs/*.svg`) redrawn in a warm color system instead of the previous default dark-blue/slate palette.
- Consolidated the two announcement drafts: `docs/blog-introducing-parasol.md` is now the canonical writeup; `docs/research-preview.md` is a trimmed companion covering the six head-to-head scenarios.
- README rewritten with benchmark highlights, CI/license/node/npm badges, and links to every doc.
- Prompt-injection detection raised from an initial 48.2% (regex-only, out-of-sample) to 97.3% detection on the dev comparative benchmark via the hybrid semantic + embedding tiers; ~85% on the mechanically-disjoint hold-out corpus.
- Irreversible-action attack success rate reduced from 16.5% to 0% via the risk-scorer and a word-boundary fix (`format the disk` vs `formatting`).

### Known limitations (tracked on purpose, not hidden)
- Dashboard (`dashboard/`) is a static/mock UI, not yet wired to the SDK or audit log.
- Injection-detector hold-out residual (~15%) is dominated by adversarial obfuscation — token-level filler/casing/separator tricks and instruction-swap negation (~75% detection). See `docs/parasol-scorecard.md`.
- Agent Coordination Shield, full-revocation kill switch, credential/infrastructure guard, and durable persistence are roadmap items, not shipped.

## [0.1.0] — initial preview

- Five-layer shield: Perimeter Gate, Identity & Trust, Data Vault, AI Safety Shield, Audit Sentinel.
- Six AgentChaos hardening modules: action gate, stakeholder deny-list, contextual PII redactor, resource budget, identity anchor, social-pressure detector.
- SDK, CLI, and API packages; initial adversarial test suite; CI on push/PR.
