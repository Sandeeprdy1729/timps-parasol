// TIMPS-Parasol · utils/scoring.ts
// TRiSM-aligned risk scoring formulae.
//
// References:
//   Gartner TRiSM — Trust, Risk and Security Management for AI Systems (2023)
//   NIST AI RMF 1.0 — AI Risk Management Framework (2023)
//   SEAgent ABAC threat modelling (Ye & Li 2024)
//
// Key outputs:
//   computeTrustScore       — composite identity trust score [0, 1]
//   computeRiskScore        — request-level risk score [0, 1] from ThreatAssessment
//   computeInjectionScore   — prompt injection risk [0, 1]
//   decayTrustScore         — apply time-based / incident-based decay
//   threatLevelFromScore    — map [0,1] score to ThreatLevel enum

import { ThreatLevel } from '../types/security.types.js';
import type { ThreatAssessment, AttackVector } from '../types/security.types.js';
import type { TrustScore } from '../types/identity.types.js';
import type { AttackPattern } from '../constants/attack-patterns.js';

// ---------------------------------------------------------------------------
// Constants  (tuneable via deployment configuration)
// ---------------------------------------------------------------------------

/** Weight of identityVerification component in the composite trust score. */
const W_IDENTITY_VERIFICATION = 0.30;
/** Weight of behavioralConsistency component. */
const W_BEHAVIORAL_CONSISTENCY = 0.25;
/** Weight of historyClean component. */
const W_HISTORY_CLEAN          = 0.25;
/** Weight of credentialStrength component. */
const W_CREDENTIAL_STRENGTH    = 0.10;
/** Weight of longevity component. */
const W_LONGEVITY               = 0.10;

/** Sum must equal 1.0 — validated at module load. */
const WEIGHT_SUM =
  W_IDENTITY_VERIFICATION +
  W_BEHAVIORAL_CONSISTENCY +
  W_HISTORY_CLEAN +
  W_CREDENTIAL_STRENGTH +
  W_LONGEVITY;

if (Math.abs(WEIGHT_SUM - 1.0) > 0.0001) {
  throw new Error(`scoring.ts: trust score weights must sum to 1.0, got ${WEIGHT_SUM}`);
}

/** Injection score normalisation cap: N weighted patterns = score 1.0. */
const INJECTION_NORMALISATION_CAP = 4.0;

/**
 * Breach count at which historyClean score reaches 0.
 * Each confirmed breach reduces the component by (1 / BREACH_ZERO_AT).
 */
const BREACH_ZERO_AT = 5;

/**
 * Number of days of clean operation that yields the maximum longevity score.
 */
const MAX_LONGEVITY_DAYS = 180;

// ---------------------------------------------------------------------------
// TrustScore computation
// ---------------------------------------------------------------------------

export interface TrustScoreInputs {
  /**
   * How well the identity has been verified.
   * Computed externally based on credential type mix and MFA status.
   *
   * Suggested values:
   *   - 0.2 = password-only
   *   - 0.5 = password + TOTP
   *   - 0.7 = Ed25519 key only
   *   - 0.9 = Passkey + Ed25519
   *   - 1.0 = Passkey + Ed25519 + certificate chain
   */
  identityVerification: number;
  /**
   * Consistency of recent request patterns (IP, UA, timing, geo).
   * Should be 1.0 for a stable, well-known client and decay toward 0
   * as spoofing indicators accumulate.
   */
  behavioralConsistency: number;
  /**
   * Number of confirmed breach records attributed to this identity.
   * Each breach reduces the historyClean component.
   */
  confirmedBreachCount: number;
  /**
   * Credential strength score, computed from the set of active credentials.
   * See `computeCredentialStrength` below.
   */
  credentialStrength: number;
  /**
   * Number of days the identity has been active without a breach.
   * Capped at MAX_LONGEVITY_DAYS for the longevity component.
   */
  cleanDays: number;
  /**
   * Optional decay factor [0, 1] to apply after computing the raw composite.
   * Use 1.0 for no decay. Values < 1 suppress the score (e.g. after an
   * active incident).
   */
  decayFactor?: number;
}

/**
 * Compute a TrustScore from the provided inputs.
 *
 * The composite is a weighted linear combination of five components,
 * optionally multiplied by a decay factor for incident suppression.
 *
 * @param inputs - See TrustScoreInputs.
 * @returns A fully populated TrustScore object.
 */
export function computeTrustScore(inputs: TrustScoreInputs): TrustScore {
  const historyClean = Math.max(
    0,
    1 - inputs.confirmedBreachCount / BREACH_ZERO_AT,
  );

  const longevity = Math.min(1, inputs.cleanDays / MAX_LONGEVITY_DAYS);

  const components: TrustScore['components'] = {
    identityVerification: clamp(inputs.identityVerification),
    behavioralConsistency: clamp(inputs.behavioralConsistency),
    historyClean,
    credentialStrength: clamp(inputs.credentialStrength),
    longevity,
  };

  const rawScore =
    components.identityVerification * W_IDENTITY_VERIFICATION +
    components.behavioralConsistency * W_BEHAVIORAL_CONSISTENCY +
    components.historyClean          * W_HISTORY_CLEAN +
    components.credentialStrength    * W_CREDENTIAL_STRENGTH +
    components.longevity             * W_LONGEVITY;

  const decayFactor = clamp(inputs.decayFactor ?? 1.0);
  const value = clamp(rawScore * decayFactor);

  // Trend is not computable from a single call; callers should compare with
  // the previous TrustScore.value to determine the trend.
  const trend: TrustScore['trend'] = 'STABLE';

  return {
    value,
    components,
    lastUpdated: new Date().toISOString(),
    trend,
    decayFactor,
  };
}

// ---------------------------------------------------------------------------
// Credential strength
// ---------------------------------------------------------------------------

/** Weight table for credential types. */
const CREDENTIAL_WEIGHTS: Record<string, number> = {
  PASSKEY:        0.95,
  ED25519_KEY:    0.90,
  CERTIFICATE:    0.85,
  API_KEY:        0.60,
  OAUTH_TOKEN:    0.55,
  PASSWORD:       0.40,
  BIOMETRIC_HASH: 0.70,
};

/**
 * Compute a credential strength score [0, 1] from a list of active credential types.
 *
 * Score = max of individual credential weights + small bonus for each additional
 * strong credential (capped at 1.0).
 *
 * @param activeCredentialTypes - List of credential type strings for this identity.
 */
export function computeCredentialStrength(activeCredentialTypes: string[]): number {
  if (activeCredentialTypes.length === 0) return 0;

  const weights = activeCredentialTypes
    .map((t) => CREDENTIAL_WEIGHTS[t] ?? 0.3)
    .sort((a, b) => b - a); // descending

  const primary = weights[0] ?? 0;
  const bonus = weights.slice(1).reduce((sum, w) => sum + w * 0.05, 0);
  return clamp(primary + bonus);
}

// ---------------------------------------------------------------------------
// TrustScore decay
// ---------------------------------------------------------------------------

/**
 * Apply incident-based and time-based decay to an existing TrustScore.
 *
 * @param current       - The current TrustScore.
 * @param newBreaches   - Number of new breach records since the last update.
 * @param incidentAlpha - Additional decay factor for an active incident [0, 1].
 *                        1.0 = no extra decay, 0.5 = halve the score.
 * @returns Updated TrustScore with `trend` populated from the delta.
 */
export function decayTrustScore(
  current: TrustScore,
  newBreaches: number,
  incidentAlpha = 1.0,
): TrustScore {
  const incidentDecay = clamp(incidentAlpha);
  const breachDecay = Math.max(0, 1 - newBreaches / BREACH_ZERO_AT);
  const newDecayFactor = clamp(current.decayFactor * incidentDecay * breachDecay);

  const newValue = clamp(current.value * newDecayFactor / (current.decayFactor || 1));
  const delta = newValue - current.value;

  let trend: TrustScore['trend'];
  if (Math.abs(delta) < 0.01) trend = 'STABLE';
  else if (delta > 0) trend = 'INCREASING';
  else trend = 'DECREASING';

  return {
    ...current,
    value: newValue,
    decayFactor: newDecayFactor,
    trend,
    lastUpdated: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Request-level risk scoring  (ThreatAssessment)
// ---------------------------------------------------------------------------

/**
 * Weight table for attack vectors.
 * Higher weight = higher contribution to the risk score.
 */
const VECTOR_WEIGHTS: Record<AttackVector, number> = {
  PROMPT_INJECTION:        0.90,
  INDIRECT_INJECTION:      0.85,
  JAILBREAK:               0.90,
  MODEL_INVERSION:         0.80,
  DATA_EXFILTRATION:       0.85,
  PRIVILEGE_ESCALATION:    0.85,
  SUPPLY_CHAIN:            0.90,
  DENIAL_OF_SERVICE:       0.75,
  SOCIAL_ENGINEERING:      0.80,
  ADVERSARIAL_INPUT:       0.75,
  TRAINING_DATA_POISONING: 0.90,
  INSECURE_OUTPUT_HANDLING:0.80,
  EXCESSIVE_AGENCY:        0.85,
  OVER_RELIANCE:           0.50,
  MODEL_THEFT:             0.80,
  CONTEXT_MANIPULATION:    0.85,
  MEMORY_POISONING:        0.85,
  TOOL_ABUSE:              0.80,
};

/**
 * Compute a request-level risk score [0, 1] from a set of detected attack vectors.
 *
 * Score = sum of vector weights, normalised with a soft cap of 3.0
 * (three high-weight vectors = score 1.0).
 *
 * @param vectors - The attack vectors detected in the request.
 * @returns Risk score in [0, 1].
 */
export function computeRiskScore(vectors: AttackVector[]): number {
  const sum = vectors.reduce((acc, v) => acc + (VECTOR_WEIGHTS[v] ?? 0.5), 0);
  return clamp(sum / 3.0);
}

/**
 * Compute the risk score from an injection pattern match result.
 *
 * @param matches - The patterns matched in the prompt.
 * @returns Score in [0, 1].
 */
export function computeInjectionScore(matches: AttackPattern[]): number {
  const sum = matches.reduce((acc, p) => acc + p.weight, 0);
  return clamp(sum / INJECTION_NORMALISATION_CAP);
}

// ---------------------------------------------------------------------------
// ThreatLevel mapping
// ---------------------------------------------------------------------------

/**
 * Map a continuous risk score [0, 1] to a discrete ThreatLevel.
 *
 * Thresholds:
 *   [0.00, 0.15) → NONE
 *   [0.15, 0.40) → LOW
 *   [0.40, 0.65) → MODERATE
 *   [0.65, 0.85) → HIGH
 *   [0.85, 1.00] → CRITICAL
 */
export function threatLevelFromScore(score: number): ThreatLevel {
  const s = clamp(score);
  if (s >= 0.85) return ThreatLevel.CRITICAL;
  if (s >= 0.65) return ThreatLevel.HIGH;
  if (s >= 0.40) return ThreatLevel.MODERATE;
  if (s >= 0.15) return ThreatLevel.LOW;
  return ThreatLevel.NONE;
}

/**
 * Map a TrustScore value [0, 1] to a ThreatLevel.
 * Lower trust = higher threat.
 *
 * Thresholds (inverse of threatLevelFromScore):
 *   [0.80, 1.00] → NONE
 *   [0.60, 0.80) → LOW
 *   [0.40, 0.60) → MODERATE
 *   [0.20, 0.40) → HIGH
 *   [0.00, 0.20) → CRITICAL
 */
export function threatLevelFromTrust(trustValue: number): ThreatLevel {
  const t = clamp(trustValue);
  if (t >= 0.80) return ThreatLevel.NONE;
  if (t >= 0.60) return ThreatLevel.LOW;
  if (t >= 0.40) return ThreatLevel.MODERATE;
  if (t >= 0.20) return ThreatLevel.HIGH;
  return ThreatLevel.CRITICAL;
}

// ---------------------------------------------------------------------------
// Composite ThreatAssessment score
// ---------------------------------------------------------------------------

/**
 * Aggregate a ThreatAssessment's vectors and confidence into a single ThreatLevel.
 *
 * Uses the maximum of:
 *   1. `threatLevelFromScore(computeRiskScore(vectors))`
 *   2. The assessment's explicitly assigned `threatLevel`
 *   3. A confidence-weighted minimum level
 */
export function aggregateThreatAssessment(assessment: ThreatAssessment): ThreatLevel {
  const scoreLevel = threatLevelFromScore(computeRiskScore(assessment.vectors));
  const confidenceLevel = assessment.confidence >= 0.8 ? assessment.threatLevel : ThreatLevel.NONE;
  return Math.max(scoreLevel, assessment.threatLevel, confidenceLevel) as ThreatLevel;
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/** Clamp a number to [0, 1]. */
function clamp(value: number): number {
  return Math.max(0, Math.min(1, value));
}

/** Exported for testing. */
export { clamp };
