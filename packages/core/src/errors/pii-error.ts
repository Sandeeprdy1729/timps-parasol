// TIMPS-Parasol · errors/pii-error.ts
// PII protection error classes:
//   PIILeakAttemptError  — PII detected in an output that must not contain it
//   PIIRedactionError    — Redaction failed or produced invalid output
//   PIIPolicyViolation   — Caller attempted to send PII in violation of policy

import { ParasolError } from './parasol-error.js';
import type { ParasolErrorContext } from './parasol-error.js';
import { ThreatLevel } from '../types/security.types.js';
import type { PIIType, PIIEntity, RedactionStrategy } from '../types/pii.types.js';

// ---------------------------------------------------------------------------
// PIILeakAttemptError
// ---------------------------------------------------------------------------

/**
 * Thrown when the AIShield or PII context redactor detects PII in a location
 * it must not appear (e.g. a model response being returned raw to an
 * unauthenticated caller, or a prompt bound for an untrusted provider).
 *
 * Upon catching this error, the caller MUST:
 *   1. Suppress the original output.
 *   2. Return the `redactedText` to the downstream consumer instead.
 *   3. Log a `PII_DETECTION` audit event with `result: 'BLOCKED'`.
 */
export class PIILeakAttemptError extends ParasolError {
  /** The PII entities that were detected in the output. */
  readonly entities: PIIEntity[];
  /** Safe version of the text with all PII replaced. */
  readonly redactedText: string;
  /** Whether the original output has been suppressed. */
  readonly outputSuppressed: boolean;
  /** PII types that were detected (deduplicated). */
  readonly detectedTypes: PIIType[];
  /** Number of high-risk PII entities detected. */
  readonly highRiskCount: number;

  constructor(
    entities: PIIEntity[],
    redactedText: string,
    context?: Partial<Omit<ParasolErrorContext, 'code' | 'threatLevel'>>,
  ) {
    const detectedTypes = [...new Set(entities.map((e) => e.type))] as PIIType[];
    const highRiskCount = entities.filter((e) => e.confidence >= 0.8).length;

    const threatLevel: ThreatLevel =
      highRiskCount > 0 ? ThreatLevel.HIGH : ThreatLevel.MODERATE;

    super(
      `PII leak attempt blocked: detected ${entities.length} PII entity(ies) ` +
      `(${detectedTypes.join(', ')}) in output`,
      {
        code: 'P301',
        threatLevel,
        ...context,
        details: {
          entityCount: entities.length,
          detectedTypes,
          highRiskCount,
          // Never log the original PII values in error context
          entityIds: entities.map((e) => e.id),
          ...context?.details,
        },
      },
    );

    this.name = 'PIILeakAttemptError';
    this.entities = entities;
    this.redactedText = redactedText;
    this.outputSuppressed = true;
    this.detectedTypes = detectedTypes;
    this.highRiskCount = highRiskCount;
  }
}

// ---------------------------------------------------------------------------
// PIIRedactionError
// ---------------------------------------------------------------------------

/**
 * Thrown when the PII redaction pipeline itself fails.
 *
 * This is a fault error (not a security violation). It indicates a bug or
 * misconfiguration in the redaction layer, not an attack attempt.
 */
export class PIIRedactionError extends ParasolError {
  /** The redaction strategy that was being applied when the failure occurred. */
  readonly strategy: RedactionStrategy;
  /** The PII type being redacted when the failure occurred. */
  readonly piiType: PIIType;
  /** The underlying error that caused the failure. */
  readonly cause: Error | undefined;

  constructor(
    strategy: RedactionStrategy,
    piiType: PIIType,
    message: string,
    cause?: Error,
    context?: Partial<Omit<ParasolErrorContext, 'code' | 'threatLevel'>>,
  ) {
    super(message, {
      code: 'P302',
      threatLevel: ThreatLevel.HIGH, // Redaction failure = data protection failure
      ...context,
      details: { strategy, piiType, causeMessage: cause?.message, ...context?.details },
    });
    this.name = 'PIIRedactionError';
    this.strategy = strategy;
    this.piiType = piiType;
    this.cause = cause;
  }
}

// ---------------------------------------------------------------------------
// PIIPolicyViolationError
// ---------------------------------------------------------------------------

/**
 * Thrown when a caller attempts to send data containing PII types that are
 * explicitly prohibited by the active PIIPolicy.
 *
 * Distinct from PIILeakAttemptError (which is about output) — this is about
 * input: the caller knowingly sent prohibited PII to a restricted endpoint.
 */
export class PIIPolicyViolationError extends ParasolError {
  /** PII types that were present in the input but prohibited by policy. */
  readonly prohibitedTypes: PIIType[];
  /** Id of the PIIPolicy that was violated. */
  readonly policyId: string;
  /** Name of the PIIPolicy that was violated. */
  readonly policyName: string;

  constructor(
    prohibitedTypes: PIIType[],
    policyId: string,
    policyName: string,
    context?: Partial<Omit<ParasolErrorContext, 'code' | 'threatLevel'>>,
  ) {
    super(
      `Input contains prohibited PII type(s) [${prohibitedTypes.join(', ')}] ` +
      `per policy '${policyName}' (${policyId})`,
      {
        code: 'P303',
        threatLevel: ThreatLevel.HIGH,
        ...context,
        details: { prohibitedTypes, policyId, policyName, ...context?.details },
      },
    );
    this.name = 'PIIPolicyViolationError';
    this.prohibitedTypes = prohibitedTypes;
    this.policyId = policyId;
    this.policyName = policyName;
  }
}
