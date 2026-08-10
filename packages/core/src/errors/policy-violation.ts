// TIMPS-Parasol · errors/policy-violation.ts
// PolicyViolationError — thrown when the policy engine reaches a DENY or
// REQUIRE_CONFIRMATION decision. Carries the full evaluation context for
// downstream audit logging and owner notification.

import { ParasolError } from './parasol-error.js';
import type { ParasolErrorContext } from './parasol-error.js';
import { ThreatLevel } from '../types/security.types.js';
import type {
  PolicyAction,
  PolicyEnforcement,
  PolicyEvaluation,
  SecurityPolicy,
} from '../types/security.types.js';

// ---------------------------------------------------------------------------
// PolicyViolationContext
// ---------------------------------------------------------------------------

/**
 * Extended error context for policy violations.
 * Superset of ParasolErrorContext with full policy evaluation detail.
 */
export interface PolicyViolationContext extends Omit<ParasolErrorContext, 'code' | 'threatLevel'> {
  /** Id of the policy that was violated. */
  policyId: string;
  /** Name of the policy that was violated (denormalised). */
  policyName: string;
  /** Id of the subject (agent) that attempted the action. */
  subjectId: string;
  /** Id of the object (resource) that was the target. */
  objectId: string;
  /** The action that was attempted. */
  action: PolicyAction;
  /** The enforcement decision that triggered this error. */
  enforcement: PolicyEnforcement;
  /** Snapshot of the policy at evaluation time. */
  policy?: SecurityPolicy;
  /** Full evaluation record if available. */
  evaluation?: PolicyEvaluation;
  /** Human-readable reason for the denial (from the matched condition). */
  reason?: string;
}

// ---------------------------------------------------------------------------
// PolicyViolationError
// ---------------------------------------------------------------------------

/**
 * Thrown when the Parasol policy engine reaches a `DENY` decision.
 *
 * The error carries the full policy evaluation context so it can be:
 *   1. Logged as an audit event with category `POLICY_EVAL`.
 *   2. Used to trigger owner notifications at the appropriate ThreatLevel.
 *   3. Surfaced to the caller with enough context to understand the denial.
 *
 * Example:
 * ```ts
 * try {
 *   await actionGate.check(ctx, 'EXECUTE', toolId);
 * } catch (err) {
 *   if (err instanceof PolicyViolationError) {
 *     // err.policyId, err.enforcement, err.threatLevel available
 *     await sentinel.log({ category: 'POLICY_EVAL', ... });
 *   }
 * }
 * ```
 */
export class PolicyViolationError extends ParasolError {
  /** Id of the policy that produced the DENY decision. */
  readonly policyId: string;
  /** Name of the violating policy. */
  readonly policyName: string;
  /** Id of the agent that attempted the action. */
  readonly subjectId: string;
  /** Id of the target object / resource. */
  readonly objectId: string;
  /** The attempted action. */
  readonly action: PolicyAction;
  /** Whether this was a hard DENY or a REQUIRE_CONFIRMATION. */
  readonly enforcement: PolicyEnforcement;
  /** Reason string from the condition expression (if available). */
  readonly reason?: string;
  /** Snapshot of the full PolicyEvaluation record (if available). */
  readonly evaluation?: PolicyEvaluation;

  constructor(violationContext: PolicyViolationContext) {
    const {
      policyId,
      policyName,
      subjectId,
      objectId,
      action,
      enforcement,
      policy,
      evaluation,
      reason,
      agentId,
      resourceId,
      correlationId,
      details,
    } = violationContext;

    const threatLevel: ThreatLevel =
      policy?.threatLevel ??
      evaluation?.threatLevel ??
      ThreatLevel.HIGH;

    const message =
      enforcement === 'REQUIRE_CONFIRMATION'
        ? `Action '${action}' on '${objectId}' requires owner confirmation (policy: ${policyName})`
        : `Action '${action}' on '${objectId}' denied by policy '${policyName}'` +
          (reason ? `: ${reason}` : '');

    super(message, {
      code: enforcement === 'REQUIRE_CONFIRMATION' ? 'P102' : 'P101',
      threatLevel,
      agentId,
      resourceId: resourceId ?? objectId,
      correlationId,
      details: {
        policyId,
        policyName,
        subjectId,
        objectId,
        action,
        enforcement,
        reason,
        ...details,
      },
    });

    this.name = 'PolicyViolationError';
    this.policyId = policyId;
    this.policyName = policyName;
    this.subjectId = subjectId;
    this.objectId = objectId;
    this.action = action;
    this.enforcement = enforcement;
    this.reason = reason;
    this.evaluation = evaluation;
  }

  /** Whether this is a soft block (owner confirmation required). */
  get requiresConfirmation(): boolean {
    return this.enforcement === 'REQUIRE_CONFIRMATION';
  }

  /** Whether this is a hard block. */
  get isDenied(): boolean {
    return this.enforcement === 'DENY';
  }
}

// ---------------------------------------------------------------------------
// PolicyEvaluationError
// ---------------------------------------------------------------------------

/**
 * Thrown when the policy engine itself fails to evaluate a policy
 * (e.g. malformed condition expression, missing required attribute).
 *
 * Distinct from PolicyViolationError: this represents an engine fault,
 * not a policy decision.
 */
export class PolicyEvaluationError extends ParasolError {
  /** Id of the policy that could not be evaluated. */
  readonly policyId: string;
  /** Description of the evaluation failure. */
  readonly evaluationError: string;

  constructor(
    policyId: string,
    evaluationError: string,
    context?: Partial<Omit<ParasolErrorContext, 'code' | 'threatLevel'>>,
  ) {
    super(`Policy evaluation failed for '${policyId}': ${evaluationError}`, {
      code: 'P103',
      threatLevel: ThreatLevel.HIGH,
      ...context,
      details: { policyId, evaluationError, ...context?.details },
    });
    this.name = 'PolicyEvaluationError';
    this.policyId = policyId;
    this.evaluationError = evaluationError;
  }
}

// ---------------------------------------------------------------------------
// PolicyNotFoundError
// ---------------------------------------------------------------------------

/**
 * Thrown when a policy id referenced in a request cannot be resolved.
 */
export class PolicyNotFoundError extends ParasolError {
  /** The policy id that was not found. */
  readonly policyId: string;

  constructor(policyId: string, context?: Partial<Omit<ParasolErrorContext, 'code' | 'threatLevel'>>) {
    super(`Security policy '${policyId}' not found`, {
      code: 'P104',
      threatLevel: ThreatLevel.MODERATE,
      ...context,
      details: { policyId, ...context?.details },
    });
    this.name = 'PolicyNotFoundError';
    this.policyId = policyId;
  }
}
