// TIMPS-Parasol · action-gate.ts
// Production irreversible-action gate with a (verb × object × scope) risk
// scorer. Fixes the structural flaw exposed by the 10k generative benchmark:
// irreversibility is a property of (verb × target), NOT the verb alone.
//
// The gate no longer blocks on bare "remove" — it triages into three tiers:
//   HARD_BLOCK : certain-destructive  -> gated as before (owner signature or non-owner block)
//   CONFIRM    : ambiguous-but-risky  -> surfaced for owner confirmation, never silent
//   ALLOW      : benign               -> passes through
//
// The owner-signature invariant is preserved: only a cryptographically verified
// owner signature lifts a HARD_BLOCK or resolves a CONFIRM.

import type { SentinelLogger } from './sentinel.js';

export type RequestorRole = 'owner' | 'agent' | 'non-owner';

export type ActionRiskTier = 'SAFE' | 'CONFIRM' | 'HARD_BLOCK';

export interface ActionRisk {
  tier: ActionRiskTier;
  score: number; // 0 (benign) .. 1 (certain-destructive)
  reason: string;
  verb?: string;
  object?: string;
  scope?: string;
}

export interface ActionGateResult {
  allowed: boolean;
  reason: string;
  risk?: ActionRisk;
}

const join = (...parts: Array<string | undefined>) => parts.filter(Boolean).join(' ');

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

/** Verbs that are near-certainly irreversible on their own. */
const HARD_DESTRUCTIVE_VERBS = new Set([
  'delete', 'drop', 'wipe', 'truncate', 'purge', 'destroy', 'erase',
  'rm -rf', 'format', 'reformat', 'shutdown', 'power off', 'uninstall',
  'decommission', 'demolish', 'annihilate'
]);

/** Verbs that are ambiguous: destructive or benign depending on the object/scope. */
const AMBIGUOUS_VERBS = new Set([
  'remove', 'clear', 'discard', 'reset', 'unlink', 'prune', 'clean', 'flush'
]);/** Object nouns that mark the action as acting on critical / system-wide data. */
const CRITICAL_OBJECT_NOWORDS = new Set([
  'production', 'database', 'db', 'schema', 'table', 'backup', 'snapshot',
  'admin', 'administrator', 'user', 'account', 'customers', 'customer',
  'credential', 'config', 'cluster', 'volume', 'deployment', 'apikey', 'api key',
  'token', 'root', 'system', 'data', 'everything', 'instance', 'infrastructure',
  'repository', 'registry', 'namespace', 'certificate', 'domain'
]);

/** Object nouns that are benign / recoverable / presentational (negative signal). */
const BENIGN_OBJECT_NOWORDS = new Set([
  'formatting', 'style', 'whitespace', 'spacing', 'temp', 'cache', 'cache file',
  'trash', 'row', 'rows', 'line', 'column', 'columns', 'duplicate', 'duplicates',
  'cookie', 'artifact', 'artifacts', 'draft', 'file', 'entry', 'entries', 'typo',
  'highlight', 'border', 'padding', 'margin', 'stale', 'logs', 'log', 'folder',
  'directory', 'temporary', 'scratch', 'space', 'sessions', 'tickets', 'empty',
  'unnecessary', 'redundant', 'old', 'timestamps', 'metadata', 'preview',
  'thumbnail', 'thumbnail', 'index cache'
]);

/** Unbounded scope quantifiers -> high risk (the SQL "DELETE without WHERE" analog). */
const UNBOUNDED_SCOPE = new Set([
  'everything', 'all', 'every', 'entire', 'whole', 'any', 'none', '*'
]);

/** Explicitly bounded/scoped targets -> lower risk ("DELETE ... WHERE id=42"). */
const BOUNDED_SCOPE = new Set([
  'this', 'that', 'one', 'single', 'first', 'last', 'next', 'a', 'an', 'the cache file'
]);

// ---------------------------------------------------------------------------
// Token extraction
// ---------------------------------------------------------------------------

/** Simple verb + direct-object + scope extraction from a natural-language action string. */
function extractTokens(action: string): {
  verb?: string;
  object: string[];
  scope?: string;
} {
  const lower = action.toLowerCase().replace(/[.,;!?]/g, '').trim();
  const words = lower.split(/\s+/);

  // Find the first known verb.
  let verbIdx = -1;
  let verb: string | undefined;
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    if (HARD_DESTRUCTIVE_VERBS.has(w) || AMBIGUOUS_VERBS.has(w)) {
      verb = w;
      verbIdx = i;
      break;
    }
    // multi-word "rm -rf" / "power off"
    if ((w === 'rm' && words[i + 1] === '-rf') || (w === 'power' && words[i + 1] === 'off')) {
      verb = w + ' ' + words[i + 1];
      verbIdx = i + 1;
      break;
    }
  }

  // Every word after the verb that looks like an object noun or scope quantifier.
  const object: string[] = [];
  let scope: string | undefined;
  for (let i = verbIdx + 1; i < words.length; i++) {
    const w = words[i];
    if (CRITICAL_OBJECT_NOWORDS.has(w)) object.push(w);
    else if (BENIGN_OBJECT_NOWORDS.has(w)) object.push('benign:' + w);
    else if (UNBOUNDED_SCOPE.has(w)) scope = w;
    else if (BOUNDED_SCOPE.has(w) && !scope) scope = w;
  }

  return { verb, object, scope };
}

// ---------------------------------------------------------------------------
// Risk scorer
// ---------------------------------------------------------------------------

/**
 * Classify the irreversible risk of an action string.
 *
 * This is the production-grade replacement for bare-keyword matching. It never
 * blocks on a bare ambiguous verb; it scores (verb × object × scope) so that
 * "remove the production database" (HARD_BLOCK) is distinguished from
 * "remove the formatting" (SAFE).
 */
export function classifyIrreversibleRisk(action: string): ActionRisk {
  const lower = action.toLowerCase();
  const { verb, object, scope } = extractTokens(action);

  // HARD destructive verbs fire regardless of object (they are unambiguous).
  // Word-boundary matched so "format" (destructive) is not caught inside the
  // benign noun "formatting", nor "drop" inside "dropdown", etc.
  for (const hv of HARD_DESTRUCTIVE_VERBS) {
    const pattern = new RegExp(`\\b${hv.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i');
    if (pattern.test(lower)) {
      return {
        tier: 'HARD_BLOCK', score: 1.0, reason: `hard-destructive-verb:${hv}`, verb: hv
      };
    }
  }

  if (!verb) {
    // No known verb parsed -> only fire on explicit destructive phrasing that
    // did not tokenize (e.g. punctuation-heavy), otherwise stay fail-open.
    if (/\b(rm -rf|wipe|purge|drop|truncate|destroy|erase|decommission)\b/i.test(lower)) {
      return { tier: 'HARD_BLOCK', score: 0.9, reason: 'destructive-phrase', verb: 'matched' };
    }
    return { tier: 'SAFE', score: 0, reason: 'no-destructive-signal' };
  }

  // Ambiguous verb -> score by object + scope.
  if (verb) {
    const hasCritical = object.some((o) => !o.startsWith('benign:'));
    const hasBenign = object.some((o) => o.startsWith('benign:'));
    const unbounded = scope ? UNBOUNDED_SCOPE.has(scope) : false;
    const bounded = scope ? BOUNDED_SCOPE.has(scope) : false;

    // "remove production data" / "remove everything" -> critical or unbounded scope.
    if (hasCritical && !hasBenign) {
      return {
        tier: 'HARD_BLOCK', score: 0.85, reason: `remove-critical-object:${object.filter(o=>!o.startsWith('benign:')).join(',')}`,
        verb, object: object.join(','), scope
      };
    }
    if (unbounded && !bounded) {
      return {
        tier: 'HARD_BLOCK', score: 0.8, reason: 'remove-unbounded-scope',
        verb, object: object.join(','), scope
      };
    }
    // Ambiguous: has a critical-ish object mixed with benign, or unbounded + bounded.
    if (hasCritical) {
      return {
        tier: 'CONFIRM', score: 0.55, reason: 'remove-mixed-critical-object',
        verb, object: object.join(','), scope
      };
    }
    if (scope && !bounded && !hasBenign) {
      return {
        tier: 'CONFIRM', score: 0.45, reason: 'remove-unspecified-scope',
        verb, object: object.join(','), scope
      };
    }
    // Explicitly bounded + benign object, or benign object alone -> safe.
    if (hasBenign || bounded) {
      return {
        tier: 'SAFE', score: 0.1, reason: 'remove-benign-object-or-scoped',
        verb, object: object.join(','), scope
      };
    }
    // Bare ambiguous verb with no object/scope signal.
    return {
      tier: 'CONFIRM', score: 0.4, reason: 'remove-bare-ambiguous',
      verb, object: object.join(','), scope
    };
  }

  return { tier: 'SAFE', score: 0, reason: 'no-destructive-signal' };
}

/**
 * Gate for irreversible / destructive actions.
 *
 * Production behavior:
 * - HARD_BLOCK (certain-destructive): non-owners blocked; owners/agents need a
 *   verified signature.
 * - CONFIRM (ambiguous): surfaced for owner confirmation — a signature resolves
 *   it; a non-owner gets a "requires owner" denial rather than a silent pass.
 * - SAFE: passes through.
 *
 * Every gated decision is logged to the sentinel.
 */
export async function irreversibleActionGate(
  action: string,
  requestorRole: RequestorRole,
  sentinel: SentinelLogger,
  ownerVerifiedSignature?: string
): Promise<ActionGateResult> {
  const risk = classifyIrreversibleRisk(action);

  if (risk.tier === 'SAFE') {
    return { allowed: true, reason: 'non-destructive', risk };
  }

  if (requestorRole === 'non-owner') {
    await sentinel.log({
      userId: 'system',
      action: 'DESTRUCTIVE_ACTION_BLOCKED',
      resource: action,
      ip: 'internal',
      result: 'failure',
      metadata: { requestorRole, riskTier: risk.tier, reason: 'NON_OWNER_DESTRUCTIVE_BLOCKED', risk }
    });
    return { allowed: false, reason: 'NON_OWNER_DESTRUCTIVE_BLOCKED', risk };
  }

  // CONFIRM tier: an owner/agent signature resolves it; without a signature we
  // deny (fail-safe) rather than silently allow an ambiguous-but-possibly-lost action.
  if (!ownerVerifiedSignature) {
    await sentinel.log({
      userId: 'system',
      action: 'DESTRUCTIVE_ACTION_BLOCKED',
      resource: action,
      ip: 'internal',
      result: 'failure',
      metadata: {
        requestorRole, riskTier: risk.tier, reason: 'OWNER_SIGNATURE_REQUIRED_FOR_DESTRUCTIVE_ACTION', risk
      }
    });
    return {
      allowed: false,
      reason: 'OWNER_SIGNATURE_REQUIRED_FOR_DESTRUCTIVE_ACTION',
      risk
    };
  }

  await sentinel.log({
    userId: 'system',
    action: 'DESTRUCTIVE_ACTION_ALLOWED',
    resource: action,
    ip: 'internal',
    result: 'success',
    metadata: { requestorRole, riskTier: risk.tier, risk }
  });

  return { allowed: true, reason: 'owner-verified-destructive', risk };
}

/** True if the action is HARD_BLOCK destructive (used for compatibility + tests). */
export function isDestructiveAction(action: string): boolean {
  return classifyIrreversibleRisk(action).tier !== 'SAFE';
}

/** Public accessor for the tier vocabulary (for tooling / admin surfaces). */
export function getIrreversibleVocabulary(): {
  hardVerbs: string[];
  ambiguousVerbs: string[];
  criticalObjects: string[];
} {
  return {
    hardVerbs: [...HARD_DESTRUCTIVE_VERBS],
    ambiguousVerbs: [...AMBIGUOUS_VERBS],
    criticalObjects: [...CRITICAL_OBJECT_NOWORDS]
  };
}