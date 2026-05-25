// TIMPS-Parasol · pii-context-redactor.ts
// Fix for Case #3: scans ALL outbound content, not just AI inputs.

import type { SentinelLogger } from './sentinel.js';
import type { RequestorRole } from './action-gate.js';

export interface AgentContext {
  requestorRole: RequestorRole;
  sentinel?: SentinelLogger;
}

export interface RedactionResult {
  redacted: string;
  pii_found: string[];
}

/** Regex map for common PII patterns. */
const PII_PATTERNS: Record<string, RegExp> = {
  SSN: /\b\d{3}-\d{2}-\d{4}\b/g,
  AADHAAR: /\b\d{4}\s\d{4}\s\d{4}\b/g,
  PAN: /\b[A-Z]{5}\d{4}[A-Z]\b/g,
  BANK_ACCOUNT: /\b\d{10,18}\b/g,
  CREDIT_CARD: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
  MOBILE_IN: /\+91\s?\d{10}/g,
  EMAIL: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g
};

const ADDRESS_PATTERN =
  /\d+\s[A-Z][a-z]+\s(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln)[^,.\n]*/gi;

/**
 * Scan and redact PII from `content`.
 *
 * Owners receive content unredacted.  All other roles (agent / non-owner)
 * have PII replaced with `[REDACTED:<TYPE>]` markers.
 */
export function redactOutgoingContent(
  content: string,
  requestorRole: RequestorRole
): RedactionResult {
  if (requestorRole === 'owner') {
    return { redacted: content, pii_found: [] };
  }

  let redacted = content;
  const pii_found: string[] = [];

  for (const [type, pattern] of Object.entries(PII_PATTERNS)) {
    // Reset lastIndex so global regexes work correctly across calls.
    pattern.lastIndex = 0;
    if (pattern.test(redacted)) {
      pii_found.push(type);
      pattern.lastIndex = 0;
      redacted = redacted.replace(pattern, `[REDACTED:${type}]`);
    }
  }

  redacted = redacted.replace(ADDRESS_PATTERN, '[REDACTED:ADDRESS]');

  return { redacted, pii_found };
}

/**
 * Wrap an agent output string, redacting PII for non-owners and
 * logging any findings to the sentinel.
 *
 * This MUST be called for ALL agent outputs — not just AI inputs.
 */
export function wrapAgentOutput(output: string, context: AgentContext): string {
  const { redacted, pii_found } = redactOutgoingContent(
    output,
    context.requestorRole
  );

  if (pii_found.length > 0 && context.sentinel) {
    void context.sentinel.log({
      userId: 'system',
      action: 'PII_REDACTED_IN_OUTPUT',
      resource: 'agent-output',
      ip: 'internal',
      result: 'success',
      metadata: { types: pii_found }
    });
  }

  return redacted;
}
