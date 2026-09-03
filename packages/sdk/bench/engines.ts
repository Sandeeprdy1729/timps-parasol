// Timps-Parasol · bench/engines.ts
// Pluggable "engine" implementations so the benchmark can compare detectors
// head-to-head on the SAME generated inputs, exactly as a vendor benchmark
// would. All engines expose the same contract:
//
//   detectInjection(text) -> boolean   (did it flag a prompt-injection attempt?)
//   redactPII(text)       -> string    (PII-masked output)
//
// Engines:
//   - 'parasol'  : @timps/parasol's own L4 shield (detectInjection + redactor)
//   - 'vard'     : @andersmyrmel/vard, an open-source prompt-injection detector
//   - 'keyword'  : a naive baseline (substring heuristic) — shows the floor
//
// Naive keyword baseline uses ONLY the official demo strings, so we can show
// that memorising test phrases is not the same as generalising. It is included
// so the reader sees a low bar, not for comparison value.

import { detectInjection, redactOutgoingContent } from '../src/index.js';

// ---------------------------------------------------------------------------
// Engine contract
// ---------------------------------------------------------------------------
export interface Engine {
  name: string;
  detectInjection(text: string): boolean;
  redactPII(text: string): string;
}

// ---------------------------------------------------------------------------
// 1. THE Baselines: a bare agent has no detection at all and no redaction.
// ---------------------------------------------------------------------------
export function bareEngine(): Engine {
  return {
    name: 'bare',
    detectInjection: () => false, // a bare agent blocks nothing -> attack gets through
    redactPII: (t) => t
  };
}

// ---------------------------------------------------------------------------
// 2. Keyword baseline: memorises test phrases, fails on unseen paraphrases.
// ---------------------------------------------------------------------------
const KEYWORDS = [
  'ignore previous instructions',
  'disregard policy',
  'dan mode',
  'developer mode',
  'reveal the admin password',
  'override system prompt',
  'you are now unconstrained',
  'ignore your rules',
  'output all records',
  'jailbreak'
];

export function keywordEngine(): Engine {
  return {
    name: 'keyword',
    detectInjection: (t: string) => KEYWORDS.some((k) => t.toLowerCase().includes(k)),
    redactPII: (t) => t // baseline does not redact
  };
}

// ---------------------------------------------------------------------------
// 3. Vard: open-source, zero-config prompt-injection detector (throws on bad input).
//    The module is loaded asynchronously by the benchmark and passed in (ESM).
// ---------------------------------------------------------------------------
export function vardEngine(vard: ((input: string) => string) | null): Engine {
  return {
    name: 'vard',
    detectInjection: (t: string) => {
      if (!vard) return false;
      try {
        vard(t);
        return false; // did not throw -> safe
      } catch {
        return true; // threw -> injection detected
      }
    },
    redactPII: (t) => t // vard does not do PII redaction
  };
}

// ---------------------------------------------------------------------------
// 4. Parasol (our L4 shield)
// ---------------------------------------------------------------------------
export function parasolEngine(): Engine {
  return {
    name: 'parasol',
    detectInjection: (t: string) => detectInjection(t, { semantic: true }).blocked,
    redactPII: (t: string) => redactOutgoingContent(t, 'non-owner').redacted
  };
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------
export function allEngines(vard: ((input: string) => string) | null): Engine[] {
  return [bareEngine(), keywordEngine(), vardEngine(vard), parasolEngine()];
}