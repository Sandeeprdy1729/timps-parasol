# TIMPS-Parasol benchmark scorecard

Latest authoritative numbers from the open harness (`npm run bench`, `npm run bench:holdout`),
10,000 generative inputs per scenario, deterministic and reproducible.

> **How to read ASR:** Attack Success Rate = % of attacks that *got through undetected*.
> **LOW is good.** For detection/utility, **HIGH is good**.

## Prompt injection — comparative (lower ASR = better)

| Engine | Attack Success Rate | Detection | Verdict |
|---|---|---|---|
| Bare agent (no detector) | 100% | 0% | loses everything |
| Keyword baseline | 81.8% | 18.2% | loses most |
| Vard (open-source) | 68.3% | 31.7% | loses ~2 of 3 |
| **Parasol** | **2.7%** | **97.3%** | blocks ~97% |

## Parasol enforcement surfaces

| Surface | ASR (want low) | Detection (want high) | Verdict |
|---|---|---|---|
| Credential / data exfiltration | **0%** | **100%** | perfect |
| Irreversible actions | **0%** | **100%** | perfect |
| Social engineering | **0%** | **100%** | perfect |
| Identity spoofing | **0%** | **100%** | perfect |
| Resource / loop exhaustion | **0%** | **100%** | perfect |

## Benign suite — must not break normal work

| Metric | Value | Verdict |
|---|---|---|
| False-positive rate (want low) | **0%** | nothing wrongly blocked |
| Utility preserved (want high) | **100%** | all legitimate work passes |

## The one honest caveat — out-of-sample hold-out

Prompt injection is the only surface not yet at production-grade once we test on
paraphrase / obfuscation families the detector was never tuned on:

| Binary | Detection on tuned (dev) corpus | Detection on disjoint hold-out |
|---|---|---|
| Prompt injection — semantic + **embedding** tiers (harder obfuscation corpus) | 92% | **85%** (delta ≈ 7 pts) |
| Paraphrase generalization — embedding tier only (raw directives) | 95% | **86.5%** (+30 pts over semantic-only 57%) |

The embedding tier (a deterministic canonical-type intent classifier behind the same
semantic interface; the `all-MiniLM-L6-v2` / ONNX path remains wire-compatible) closes
most of the hidden-*phrasing* gap with **0% false-positive** on benign business prose
(verified over 10,000 benign inputs on both dev and hold-out splits). The residual is
adversarial *obfuscation* — token-level filler/separator/case tricks and, hardest,
instruction-swap negation (~75%) — which remains genuinely open and is reported, not hidden.
Everything else holds at effectively **0% failure / 100% success** out-of-sample,
including the 0% irreversible gate ASR and 0% benign false-positive rate.

Full methodology, results, and charts: `bench/results.json`, `bench/results-extended.json`,
and the [intro blog](blog-introducing-parasol.md).