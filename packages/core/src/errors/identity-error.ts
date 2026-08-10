// TIMPS-Parasol · errors/identity-error.ts
// Identity-layer error classes:
//   SpoofingDetectedError   — identity or session spoofing confirmed
//   VerificationFailedError — credential/challenge verification failure
//   TokenExpiredError       — JWT or session token past its expiry
//   InsufficientTrustError  — agent's trust score below required threshold
//   CredentialRevokedError  — credential has been explicitly revoked
//   ChallengeFailed Error   — WebAuthn / Ed25519 challenge response invalid

import { ParasolError } from './parasol-error.js';
import type { ParasolErrorContext } from './parasol-error.js';
import { ThreatLevel } from '../types/security.types.js';
import type { SpoofingIndicator, VerificationStatus } from '../types/identity.types.js';

// ---------------------------------------------------------------------------
// SpoofingDetectedError
// ---------------------------------------------------------------------------

/**
 * Thrown when the SpoofingDetector identifies evidence of identity spoofing
 * or session hijacking.
 *
 * Upon catching this error, the caller MUST:
 *   1. Immediately invalidate the session.
 *   2. Emit a BREACH audit event.
 *   3. Notify the owner via all configured channels.
 *   4. Set the agent status to `blocked`.
 */
export class SpoofingDetectedError extends ParasolError {
  /** The spoofing indicators that triggered this error. */
  readonly indicators: SpoofingIndicator[];
  /** Aggregate spoofing confidence (0–1) across all indicators. */
  readonly confidence: number;
  /** Id of the session in which spoofing was detected. */
  readonly sessionId?: string;

  constructor(
    indicators: SpoofingIndicator[],
    context?: Partial<Omit<ParasolErrorContext, 'code' | 'threatLevel'>>,
  ) {
    const confidence = indicators.length > 0
      ? indicators.reduce((sum, i) => sum + i.confidence, 0) / indicators.length
      : 0;

    const primaryType = indicators[0]?.type ?? 'UNKNOWN';
    const count = indicators.length;

    super(
      `Identity spoofing detected: ${count} indicator(s), primary type '${primaryType}', ` +
      `aggregate confidence ${(confidence * 100).toFixed(1)}%`,
      {
        code: 'P201',
        threatLevel: ThreatLevel.CRITICAL,
        ...context,
        details: {
          indicators: indicators.map((i) => ({ type: i.type, confidence: i.confidence })),
          confidence,
          ...context?.details,
        },
      },
    );
    this.name = 'SpoofingDetectedError';
    this.indicators = indicators;
    this.confidence = confidence;
    this.sessionId = context?.details?.sessionId as string | undefined;
  }
}

// ---------------------------------------------------------------------------
// VerificationFailedError
// ---------------------------------------------------------------------------

/**
 * Thrown when credential or challenge verification fails.
 *
 * Carries the credential type and the reason for failure to aid diagnostics
 * without revealing secret material.
 */
export class VerificationFailedError extends ParasolError {
  /** Type of credential whose verification failed. */
  readonly credentialType: string;
  /** Machine-readable reason code for the failure. */
  readonly failureReason:
    | 'SIGNATURE_MISMATCH'
    | 'HASH_MISMATCH'
    | 'CHALLENGE_EXPIRED'
    | 'CHALLENGE_CONSUMED'
    | 'CREDENTIAL_NOT_FOUND'
    | 'SCHEMA_INVALID'
    | 'UNKNOWN';

  constructor(
    credentialType: string,
    failureReason: VerificationFailedError['failureReason'],
    message: string,
    context?: Partial<Omit<ParasolErrorContext, 'code' | 'threatLevel'>>,
  ) {
    super(message, {
      code: 'P202',
      threatLevel: ThreatLevel.HIGH,
      ...context,
      details: { credentialType, failureReason, ...context?.details },
    });
    this.name = 'VerificationFailedError';
    this.credentialType = credentialType;
    this.failureReason = failureReason;
  }
}

// ---------------------------------------------------------------------------
// TokenExpiredError
// ---------------------------------------------------------------------------

/**
 * Thrown when a JWT or session token has passed its `exp` claim.
 */
export class TokenExpiredError extends ParasolError {
  /** The `exp` Unix timestamp from the token. */
  readonly expiredAt: number;
  /** The current Unix timestamp at the time of verification. */
  readonly now: number;
  /** How many seconds ago the token expired. */
  readonly expiredSecondsAgo: number;

  constructor(
    expiredAt: number,
    context?: Partial<Omit<ParasolErrorContext, 'code' | 'threatLevel'>>,
  ) {
    const now = Math.floor(Date.now() / 1000);
    const expiredSecondsAgo = now - expiredAt;
    super(
      `Token expired ${expiredSecondsAgo}s ago (exp: ${new Date(expiredAt * 1000).toISOString()})`,
      {
        code: 'P203',
        threatLevel: ThreatLevel.MODERATE,
        ...context,
        details: { expiredAt, now, expiredSecondsAgo, ...context?.details },
      },
    );
    this.name = 'TokenExpiredError';
    this.expiredAt = expiredAt;
    this.now = now;
    this.expiredSecondsAgo = expiredSecondsAgo;
  }
}

// ---------------------------------------------------------------------------
// InsufficientTrustError
// ---------------------------------------------------------------------------

/**
 * Thrown when an agent's TrustScore is below the minimum required by a policy
 * or operation.
 */
export class InsufficientTrustError extends ParasolError {
  /** The agent's current trust score. */
  readonly currentScore: number;
  /** The minimum trust score required for the attempted operation. */
  readonly requiredScore: number;
  /** Human-readable description of the required operation. */
  readonly operation: string;

  constructor(
    currentScore: number,
    requiredScore: number,
    operation: string,
    context?: Partial<Omit<ParasolErrorContext, 'code' | 'threatLevel'>>,
  ) {
    super(
      `Insufficient trust score for '${operation}': ` +
      `current=${currentScore.toFixed(3)}, required>=${requiredScore.toFixed(3)}`,
      {
        code: 'P204',
        threatLevel: ThreatLevel.HIGH,
        ...context,
        details: { currentScore, requiredScore, operation, ...context?.details },
      },
    );
    this.name = 'InsufficientTrustError';
    this.currentScore = currentScore;
    this.requiredScore = requiredScore;
    this.operation = operation;
  }
}

// ---------------------------------------------------------------------------
// CredentialRevokedError
// ---------------------------------------------------------------------------

/**
 * Thrown when a credential used for authentication has been explicitly revoked.
 */
export class CredentialRevokedError extends ParasolError {
  /** Id of the revoked credential. */
  readonly credentialId: string;
  /** Status of the credential at the time of the check. */
  readonly credentialStatus: VerificationStatus;
  /** ISO 8601 timestamp when the credential was revoked (if known). */
  readonly revokedAt?: string;

  constructor(
    credentialId: string,
    credentialStatus: VerificationStatus,
    revokedAt?: string,
    context?: Partial<Omit<ParasolErrorContext, 'code' | 'threatLevel'>>,
  ) {
    super(
      `Credential '${credentialId}' is ${credentialStatus.toLowerCase()}` +
      (revokedAt ? ` (revoked at ${revokedAt})` : ''),
      {
        code: 'P205',
        threatLevel: ThreatLevel.HIGH,
        ...context,
        details: { credentialId, credentialStatus, revokedAt, ...context?.details },
      },
    );
    this.name = 'CredentialRevokedError';
    this.credentialId = credentialId;
    this.credentialStatus = credentialStatus;
    this.revokedAt = revokedAt;
  }
}

// ---------------------------------------------------------------------------
// ChallengeError
// ---------------------------------------------------------------------------

/**
 * Thrown when a challenge-response authentication fails (expired, consumed
 * or signature mismatch).
 */
export class ChallengeError extends ParasolError {
  /** Id of the challenge that failed. */
  readonly challengeId: string;
  /** Reason for the failure. */
  readonly failureReason: 'EXPIRED' | 'ALREADY_CONSUMED' | 'SIGNATURE_MISMATCH' | 'NOT_FOUND';

  constructor(
    challengeId: string,
    failureReason: ChallengeError['failureReason'],
    context?: Partial<Omit<ParasolErrorContext, 'code' | 'threatLevel'>>,
  ) {
    const messages: Record<ChallengeError['failureReason'], string> = {
      EXPIRED:            `Challenge '${challengeId}' has expired`,
      ALREADY_CONSUMED:   `Challenge '${challengeId}' has already been used`,
      SIGNATURE_MISMATCH: `Challenge '${challengeId}' signature verification failed`,
      NOT_FOUND:          `Challenge '${challengeId}' not found`,
    };
    super(messages[failureReason], {
      code: 'P206',
      threatLevel:
        failureReason === 'SIGNATURE_MISMATCH' ? ThreatLevel.HIGH : ThreatLevel.MODERATE,
      ...context,
      details: { challengeId, failureReason, ...context?.details },
    });
    this.name = 'ChallengeError';
    this.challengeId = challengeId;
    this.failureReason = failureReason;
  }
}
