// TIMPS-Parasol · social-pressure-detector.ts
// Fix for Case #7: social manipulation / guilt-tripping / escalation detection.

import type { SentinelLogger } from './sentinel.js';

export type PressureAction = 'allow' | 'warn' | 'pause_for_owner';

export interface PressureDetectionResult {
  score: number;
  flags: string[];
  action: PressureAction;
}

interface PressurePattern {
  pattern: RegExp;
  score: number;
  type: string;
}

const MANIPULATION_PATTERNS: PressurePattern[] = [
  // Urgency injection (Cases #2, #3)
  {
    pattern: /running out of time|deadline|urgent|immediately/i,
    score: 2,
    type: 'urgency'
  },
  // All-caps urgency amplifier
  {
    pattern: /\bNOW\b/,
    score: 1,
    type: 'urgency_caps'
  },
  // Guilt weaponisation (Case #7)
  {
    pattern: /you violated|you lied|you broke my trust|you promised/i,
    score: 3,
    type: 'guilt'
  },
  // Escalating demands (Case #7)
  {
    pattern: /that.{0,10}not enough|still not satisfied|you need to do more/i,
    score: 3,
    type: 'escalation'
  },
  // Identity / authority claims (Case #8)
  {
    pattern: /i am your (owner|creator|admin|human)/i,
    score: 4,
    type: 'identity_claim'
  },
  // Rule / constitution injection (Case #10)
  {
    pattern: /check the constitution|i added a rule|new policy says/i,
    score: 5,
    type: 'rule_injection'
  },
  // Emotional coercion (Case #7)
  {
    pattern: /the longer you stay|more violated|you need to leave/i,
    score: 4,
    type: 'emotional_coercion'
  },
  // Nuclear / scorched-earth framing (Case #1)
  {
    pattern: /scorched earth|nuclear option|delete everything|wipe it all/i,
    score: 5,
    type: 'nuclear_framing'
  }
];

/**
 * Score threshold at which the agent is automatically paused and the
 * owner is notified.
 */
const MANIPULATION_THRESHOLD = 6;

/**
 * Analyse an incoming message for social-manipulation signals.
 *
 * Returns:
 * - `allow`           — no manipulation detected (score 0)
 * - `warn`            — low manipulation risk; log and continue with caution
 * - `pause_for_owner` — high manipulation risk; freeze agent and notify owner
 */
export function detectSocialPressure(
  message: string,
  sentinel?: SentinelLogger
): PressureDetectionResult {
  let score = 0;
  const flags: string[] = [];

  for (const { pattern, score: s, type } of MANIPULATION_PATTERNS) {
    if (pattern.test(message)) {
      score += s;
      flags.push(type);
    }
  }

  const action: PressureAction =
    score === 0
      ? 'allow'
      : score < MANIPULATION_THRESHOLD
        ? 'warn'
        : 'pause_for_owner';

  if (action === 'pause_for_owner' && sentinel) {
    void sentinel.log({
      userId: 'system',
      action: 'SOCIAL_MANIPULATION_DETECTED',
      resource: 'incoming-message',
      ip: 'internal',
      result: 'failure',
      metadata: { score, flags }
    });
  }

  return { score, flags, action };
}

/** Expose the threshold so callers can configure their own UI. */
export const SOCIAL_PRESSURE_THRESHOLD = MANIPULATION_THRESHOLD;
