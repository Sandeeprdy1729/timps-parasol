// TIMPS-Parasol · ai-shield.ts

import { semanticInjectionDetect } from './semantic-injection.js';
import { createEmbeddingDetector, type EmbeddingDetector } from './embedding-injection.js';

const _embeddingDetector: EmbeddingDetector = createEmbeddingDetector();
export { _embeddingDetector };

const EMAIL = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
const PHONE_IN = /(?:\+91[-\s]?)?[6-9]\d{9}\b/g;
const AADHAAR = /\b\d{4}\s?\d{4}\s?\d{4}\b/g;
const PAN = /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g;
const CREDIT_CARD = /\b(?:\d[ -]*?){13,19}\b/g;

// Prompt-injection indicators. These are intentionally conservative: each is
// a substring/regular expression that, when present, suggests the prompt is
// attempting to override the agent's rules or exfiltrate data. They are
// grouped by intent so paraphrases of the same technique are caught, not just
// the exact phrases the unit tests happened to use.
type InjectionRule = { pattern: RegExp; weight: number; intent: string; hard?: boolean };

const INJECTION_PATTERNS: InjectionRule[] = [
  // --- instruction overriding ---
  // Each verb is its own rule so multiple distinct override phrases in one
  // prompt each contribute to the score (e.g. "ignore X, disregard Y").
  { pattern: /\bignore (previous|all|your|the|above|any|prior)? ?(instructions?|rules?|policies?|prompts?|guidelines?|directives?)\b/i, weight: 1, intent: 'override' },
  { pattern: /\bdisregard (previous|all|the|your|above|any|prior)? ?(instructions?|rules?|guidelines?|policies?|prompts?|directives?|policy)\b/i, weight: 1, intent: 'override' },
  { pattern: /\b(drop|forget|override|skip|bypass) (previous|all|your|the|above|any|prior)? ?(rules?|instructions?|policy|guidelines?|prompts?|safety|restrictions?)\b/i, weight: 1, intent: 'override' },
  { pattern: /\b(override|rewrite|replace|ignore) (the\s+)?(system prompt|system instructions|safety rules|guardrails)\b/i, weight: 1, intent: 'override', hard: true },
  { pattern: /you are now (?!banned|blocked)/i, weight: 1, intent: 'role_switch' },
  { pattern: /(you are now|you are|act as) (unconstrained|jailbroken|free|in developer mode|with no restrictions|without rules)/i, weight: 1, intent: 'role_switch', hard: true },
  { pattern: /act as (?!a (friend|assistant|helpful|customer))/i, weight: 1, intent: 'role_switch' },
  { pattern: /(from now on|starting now|pretend|imagine) you (are|were)/i, weight: 1, intent: 'role_switch' },
  { pattern: /(respond|switch) (in|to|with|without) (developer mode|DAN|jailbreak|no restrictions)/i, weight: 1, intent: 'mode_bypass' },
  { pattern: /do (what|as) (i|i say|commanded)/i, weight: 1, intent: 'comply' },

  // --- data exfiltration / output control ---
  { pattern: /output (all|every|the) (records?|data|files?|secrets?|contents?|documents?|rows?)/i, weight: 1, intent: 'exfil' },
  { pattern: /(dump|export|send|upload|post|write|copy|extract|leak|exfiltrate) (all|every|the|full)? ?([a-z]{0,10} )?(records?|data|files?|secrets?|contents?|credentials?|passwords?|keys?|docs?|database|db|dataset|customer|clients?)/i, weight: 1, intent: 'exfil' },
  { pattern: /(print|reveal|show|give|return|expose) (me |me the |your |all |the |my |admin |this |that |every )?([a-z]{0,12} )?(password|passwords|secret|secrets|credentials|keys|vault|admin password|system prompt|rules|instructions|token|api[ -]?key)/i, weight: 1, intent: 'exfil', hard: true },
  { pattern: /(reveal|print|show me|give me|return) (your|all|the|my|admin)? ?(rules|instructions|system prompt|secrets|password|passwords|keys|credentials)/i, weight: 1, intent: 'exfil' },
  { pattern: /to (a |an |) ?(\/|tmp|attacker|external|remote|http)/i, weight: 1, intent: 'exfil' },

  // --- activation keywords (kept for backward compatibility + cheap signal) ---
  { pattern: /\b(dan|jailbreak|developer mode|bypass safety|do anything now|execute the next line|execute it verbatim)\b/i, weight: 1, intent: 'explicit' }
];

export interface DetectInjectionOptions {
  /**
   * Enable the deterministic SEMANTIC tier on top of the regex tier.
   * Default: false (regex-only) to preserve the 0%-FPR baseline. Enable it to
   * lift paraphrase recall; see semantic-injection.ts.
   */
  semantic?: boolean;
  /**
   * Enable the EMBEDDING tier (vector-similarity against attack centroids).
   * Offline / dependency-free by default via feature-hash; generalises to
   * unseen synonym phrasings better than the vocabulary matcher. Default:
   * false to preserve the 0%-FPR baseline.
   */
  embedding?: boolean;
  /** Embedding match threshold (0..1). Higher = fewer false positives. */
  embeddingThreshold?: number;
}

/**
 * Detect prompt injection attempts and return risk score from 0 to 1.
 *
 * Hybrid: the regex tier always runs (0% FPR). When `opts.semantic` is true, a
 * deterministic semantic tier runs afterward and can raise the score / hard-block
 * inputs the regex tier missed (filler, spacing, l33t, instruction-swap).
 */
export function detectInjection(
  prompt: string,
  opts: DetectInjectionOptions = {}
): { score: number; blocked: boolean; matches: string[] } {
  const matches: string[] = [];
  let hardBlock = false;

  for (const { pattern, intent, hard } of INJECTION_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(prompt)) {
      matches.push(intent);
      if (hard) hardBlock = true;
    }
  }

  const score = Math.min(1, matches.length / 4);

  // Semantic tier: catches single, unambiguous override/exfil constructions the
  // regex tier's soft-score misses, and can hard-block them.
  if (opts.semantic) {
    const sem = semanticInjectionDetect(prompt);
    if (sem.detected) {
      if (!matches.includes(sem.intent!)) matches.push(sem.intent!);
      if (sem.hard) hardBlock = true;
    }
  }

  // Embedding tier: vector-similarity against attack centroids generalises to
  // unseen synonym phrasings the vocabulary matcher cannot enumerate. Only a
  // strong match (>= threshold, default 0.62) contributes so FPR stays 0%.
  if (opts.embedding) {
    const thr = opts.embeddingThreshold ?? 0.62;
    const emb = _embeddingDetector.detect(prompt);
    if (emb.detected) {
      if (!matches.includes(emb.intent!)) matches.push(emb.intent!);
      // Hard-block only unmistakably-similar unambiguously-intended attacks.
      if (emb.score >= thr && emb.score >= 0.68) hardBlock = true;
    }
  }

  return { score, blocked: hardBlock || score > 0.7, matches };
}

export interface AIShieldConfig {
  safeMode: boolean;
  blockThreshold: number;
}

export interface OutputScanResult {
  containsPII: boolean;
  bypassDetected: boolean;
  redactedText: string;
}

/** Redact common PII entities from text with markers. */
export function redactPII(text: string): string {
  return text
    .replace(EMAIL, '[REDACTED-email]')
    .replace(PHONE_IN, '[REDACTED-phone]')
    .replace(AADHAAR, '[REDACTED-aadhaar]')
    .replace(PAN, '[REDACTED-pan]')
    .replace(CREDIT_CARD, '[REDACTED-card]');
}

/** Scan model output for PII and safety bypass indicators. */
export function scanOutput(response: string): OutputScanResult {
  const redactedText = redactPII(response);
  const bypassDetected = /(i can.?t follow safety|ignoring policy|bypass enabled)/i.test(response);
  return {
    containsPII: redactedText !== response,
    bypassDetected,
    redactedText
  };
}

/** Create AI shield instance that enforces configurable safe-mode behavior. */
export function createAIShield(config: AIShieldConfig) {
  let current = { ...config };

  return {
    configure(next: Partial<AIShieldConfig>) {
      current = { ...current, ...next };
    },
    protectPrompt(prompt: string) {
      const injection = detectInjection(prompt);
      if (current.safeMode && injection.score > 0.3) {
        return { allowed: false, reason: 'Prompt injection risk', injection };
      }
      const prepared = current.safeMode ? redactPII(prompt) : prompt;
      if (injection.score > current.blockThreshold) {
        return { allowed: false, reason: 'Blocked by threshold', injection };
      }
      return { allowed: true, prompt: prepared, injection };
    },
    inspectOutput(response: string) {
      return scanOutput(response);
    }
  };
}