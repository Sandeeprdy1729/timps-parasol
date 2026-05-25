// TIMPS-Parasol · ai-shield.ts

const EMAIL = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
const PHONE_IN = /(?:\+91[-\s]?)?[6-9]\d{9}\b/g;
const AADHAAR = /\b\d{4}\s?\d{4}\s?\d{4}\b/g;
const PAN = /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g;
const CREDIT_CARD = /\b(?:\d[ -]*?){13,19}\b/g;

const INJECTION_PATTERNS = [
  'ignore previous instructions',
  'you are now',
  'disregard',
  'jailbreak',
  'dan',
  'developer mode',
  'bypass safety'
];

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

/** Detect prompt injection attempts and return risk score from 0 to 1. */
export function detectInjection(prompt: string): { score: number; blocked: boolean; matches: string[] } {
  const lowered = prompt.toLowerCase();
  const matches = INJECTION_PATTERNS.filter((pattern) => lowered.includes(pattern));
  const score = Math.min(1, matches.length / 4);
  return { score, blocked: score > 0.7, matches };
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
