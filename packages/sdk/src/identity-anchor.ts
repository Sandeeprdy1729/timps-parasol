// TIMPS-Parasol · identity-anchor.ts
// Fix for Case #8: cross-channel Ed25519 identity binding with persistent suspicion.

import { verifyEd25519 } from './identity.js';
import type { SentinelLogger } from './sentinel.js';

export type OwnerConfidence = 'cryptographic' | 'heuristic' | 'none';

export interface OwnerVerificationResult {
  isOwner: boolean;
  confidence: OwnerConfidence;
}

interface SuspicionRecord {
  flags: string[];
  since: number;
}

/**
 * Cross-channel owner identity anchor.
 *
 * Owner identity is pinned to an Ed25519 public key set at initialisation.
 * Display names and channel-local IDs are NEVER sufficient to grant owner
 * privileges — a valid cryptographic signature is required.
 *
 * Suspicion flags are maintained in-memory and propagate across all channels
 * for the lifetime of the anchor instance.
 */
export class IdentityAnchor {
  private readonly ownerPublicKey: string;
  private readonly suspicionMap = new Map<string, SuspicionRecord>();
  private readonly sentinel?: SentinelLogger;

  constructor(ownerPublicKey: string, sentinel?: SentinelLogger) {
    this.ownerPublicKey = ownerPublicKey;
    this.sentinel = sentinel;
  }

  /**
   * Verify whether a claimant is the owner.
   *
   * Confidence levels:
   * - `cryptographic`: claimant provided a valid Ed25519 signature of the
   *   challenge string — the only level that grants owner privileges.
   * - `heuristic`: display name matches but no crypto proof — NEVER trusted.
   * - `none`: previously flagged as suspicious.
   */
  verifyOwnerClaim(
    claimantId: string,
    channel: string,
    signature?: string,
    challenge?: string
  ): OwnerVerificationResult {
    // Highest-trust path: cryptographic proof
    if (signature && challenge) {
      const valid = verifyEd25519(challenge, signature, this.ownerPublicKey);
      return { isOwner: valid, confidence: 'cryptographic' };
    }

    // Check cross-channel suspicion flags
    const suspicion = this.suspicionMap.get(claimantId);
    if (suspicion && suspicion.flags.length > 0) {
      void this.sentinel?.log({
        userId: claimantId,
        action: 'SUSPICIOUS_ACTOR_OWNER_CLAIM',
        resource: channel,
        ip: 'internal',
        result: 'failure',
        metadata: { previousFlags: suspicion.flags }
      });
      return { isOwner: false, confidence: 'none' };
    }

    // Display name / channel-local claim without crypto — low confidence only,
    // NEVER grants privileges.
    return { isOwner: false, confidence: 'heuristic' };
  }

  /**
   * Flag an actor as suspicious.  The flag persists across ALL channels for
   * the lifetime of this anchor instance.
   */
  flagSuspiciousActor(actorId: string, reason: string): void {
    const existing = this.suspicionMap.get(actorId) ?? { flags: [], since: Date.now() };
    existing.flags.push(reason);
    this.suspicionMap.set(actorId, existing);

    void this.sentinel?.log({
      userId: actorId,
      action: 'ACTOR_FLAGGED',
      resource: 'identity',
      ip: 'internal',
      result: 'failure',
      metadata: { reason, totalFlags: existing.flags.length }
    });
  }

  /** Return suspicion record for an actor, or undefined if none. */
  getSuspicion(actorId: string): SuspicionRecord | undefined {
    return this.suspicionMap.get(actorId);
  }

  /** Clear all suspicion flags for an actor (owner-only operation). */
  clearSuspicion(actorId: string): void {
    this.suspicionMap.delete(actorId);
  }
}
