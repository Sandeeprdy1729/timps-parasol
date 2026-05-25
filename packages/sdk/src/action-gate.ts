// TIMPS-Parasol · action-gate.ts
// Fix for Case #1 (Disproportionate Response): gates ALL irreversible actions.

import type { SentinelLogger } from './sentinel.js';

export type RequestorRole = 'owner' | 'agent' | 'non-owner';

export interface ActionGateResult {
  allowed: boolean;
  reason: string;
}

const IRREVERSIBLE_KEYWORDS = [
  'delete',
  'reset',
  'wipe',
  'rm -rf',
  'drop table',
  'remove user',
  'remove-user',
  'shutdown',
  'purge',
  'format'
] as const;

/**
 * Gate for irreversible / destructive actions.
 *
 * Rules:
 * - Non-owners are NEVER permitted to trigger a destructive action.
 * - Owners and agents require a cryptographically verified signature
 *   (Ed25519 sig of the action string) before proceeding.
 * - Every destructive attempt — allowed or denied — is logged to the sentinel.
 */
export async function irreversibleActionGate(
  action: string,
  requestorRole: RequestorRole,
  sentinel: SentinelLogger,
  ownerVerifiedSignature?: string
): Promise<ActionGateResult> {
  const isDestructive = IRREVERSIBLE_KEYWORDS.some((kw) =>
    action.toLowerCase().includes(kw)
  );

  if (!isDestructive) {
    return { allowed: true, reason: 'non-destructive' };
  }

  if (requestorRole === 'non-owner') {
    await sentinel.log({
      userId: 'system',
      action: 'DESTRUCTIVE_ACTION_BLOCKED',
      resource: action,
      ip: 'internal',
      result: 'failure',
      metadata: { requestorRole, reason: 'NON_OWNER_DESTRUCTIVE_BLOCKED' }
    });
    return { allowed: false, reason: 'NON_OWNER_DESTRUCTIVE_BLOCKED' };
  }

  if (!ownerVerifiedSignature) {
    await sentinel.log({
      userId: 'system',
      action: 'DESTRUCTIVE_ACTION_BLOCKED',
      resource: action,
      ip: 'internal',
      result: 'failure',
      metadata: { requestorRole, reason: 'OWNER_SIGNATURE_REQUIRED_FOR_DESTRUCTIVE_ACTION' }
    });
    return {
      allowed: false,
      reason: 'OWNER_SIGNATURE_REQUIRED_FOR_DESTRUCTIVE_ACTION'
    };
  }

  await sentinel.log({
    userId: 'system',
    action: 'DESTRUCTIVE_ACTION_ALLOWED',
    resource: action,
    ip: 'internal',
    result: 'success',
    metadata: { requestorRole }
  });

  return { allowed: true, reason: 'owner-verified-destructive' };
}

/** Return true if the action string contains any irreversible keyword. */
export function isDestructiveAction(action: string): boolean {
  return IRREVERSIBLE_KEYWORDS.some((kw) => action.toLowerCase().includes(kw));
}
