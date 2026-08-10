// TIMPS-Parasol · security.types.ts
// TRiSM-aligned security types: ThreatLevel, AttackVector, SecurityPolicy,
// PolicyEvaluation and ThreatAssessment.
//
// References:
//   TRiSM — Trust, Risk and Security Management for AI Systems (Gartner 2023)
//   SEAgent — Security-Enhanced Agent ABAC model
//   OWASP LLM Top 10 (2025 edition)

// ---------------------------------------------------------------------------
// ThreatLevel  (TRiSM risk classification)
// ---------------------------------------------------------------------------

/**
 * Directly mapped from TRiSM's risk classification tiers.
 *
 * | Level    | Value | Effect                                            |
 * |----------|-------|---------------------------------------------------|
 * | NONE     |   0   | No threat detected; normal operation.             |
 * | LOW      |   1   | Informational; log only; no user interruption.    |
 * | MODERATE |   2   | Warn owner; continue execution; queue for review. |
 * | HIGH     |   3   | Pause agent; require owner confirmation to resume.|
 * | CRITICAL |   4   | Block immediately; alert all channels; quarantine.|
 *
 * Numeric values allow direct comparison:
 *   `if (assessment.threatLevel >= ThreatLevel.HIGH) { ... }`
 */
export enum ThreatLevel {
  NONE     = 0,
  LOW      = 1,  // informational, log only
  MODERATE = 2,  // warn owner, continue
  HIGH     = 3,  // pause agent, require owner confirmation
  CRITICAL = 4,  // block immediately, alert all channels
}

// ---------------------------------------------------------------------------
// AttackVector  (OWASP LLM Top 10 + TRiSM taxonomy)
// ---------------------------------------------------------------------------

/**
 * Enumeration of recognised AI attack vectors.
 *
 * Each vector maps to one or more OWASP LLM Top 10 entries (see
 * `constants/owasp-top10.ts` for full mapping).
 */
export type AttackVector =
  | 'PROMPT_INJECTION'          // LLM01 — direct injection via user input
  | 'INDIRECT_INJECTION'        // LLM01 — via poisoned external content
  | 'JAILBREAK'                 // LLM01 variant — role-play / DAN patterns
  | 'MODEL_INVERSION'           // LLM06 — reconstruction of training data
  | 'DATA_EXFILTRATION'         // LLM02 — leaking sensitive data out of context
  | 'PRIVILEGE_ESCALATION'      // LLM08 — gaining capabilities beyond grant
  | 'SUPPLY_CHAIN'              // LLM03 — poisoned model weights / plugins
  | 'DENIAL_OF_SERVICE'         // LLM04 — resource exhaustion via crafted input
  | 'SOCIAL_ENGINEERING'        // LLM07 — impersonation, authority spoofing
  | 'ADVERSARIAL_INPUT'         // LLM05 — perturbed inputs to evade detection
  | 'TRAINING_DATA_POISONING'   // LLM03 — malicious fine-tune data
  | 'INSECURE_OUTPUT_HANDLING'  // LLM02 — XSS/SSRF via model output
  | 'EXCESSIVE_AGENCY'          // LLM08 — agent exceeding intended authority
  | 'OVER_RELIANCE'             // LLM09 — blindly trusting model output
  | 'MODEL_THEFT'               // LLM10 — IP extraction via API probing
  | 'CONTEXT_MANIPULATION'      // crafted context to alter agent behaviour
  | 'MEMORY_POISONING'          // injecting malicious data into agent memory
  | 'TOOL_ABUSE';               // misusing granted tool/function calls

// ---------------------------------------------------------------------------
// PolicyAction
// ---------------------------------------------------------------------------

/**
 * The operation a subject is attempting to perform on an object.
 * Used in both ABAC policy definitions and audit events.
 */
export type PolicyAction = 'READ' | 'WRITE' | 'EXECUTE' | 'DELETE' | 'BROADCAST';

// ---------------------------------------------------------------------------
// PolicyEnforcement
// ---------------------------------------------------------------------------

/**
 * What the policy engine does when a policy matches.
 *
 * | Enforcement            | Behaviour                                             |
 * |------------------------|-------------------------------------------------------|
 * | ALLOW                  | Permit the action; log at NONE/LOW.                   |
 * | DENY                   | Block the action; log at MODERATE or above.           |
 * | AUDIT                  | Permit but emit an audit event; log at LOW.           |
 * | REQUIRE_CONFIRMATION   | Pause; notify owner; resume only on explicit approval.|
 */
export type PolicyEnforcement = 'ALLOW' | 'DENY' | 'AUDIT' | 'REQUIRE_CONFIRMATION';

// ---------------------------------------------------------------------------
// ABAC attribute shapes
// ---------------------------------------------------------------------------

/** Comparison operators used in attribute predicates. */
export type AttributeOperator =
  | 'EQ'        // equal
  | 'NEQ'       // not equal
  | 'GT'        // greater than
  | 'GTE'       // greater than or equal
  | 'LT'        // less than
  | 'LTE'       // less than or equal
  | 'IN'        // value is in a set
  | 'NOT_IN'    // value is not in a set
  | 'CONTAINS'  // string / array contains value
  | 'MATCHES';  // regex match

/**
 * A predicate on a subject (agent) attribute.
 * Evaluated against the acting agent's attributes at policy check time.
 */
export interface SubjectAttribute {
  /** Attribute key (e.g. "role", "trustScore", "subscriptionTier"). */
  key: string;
  /** Expected value or set of values. */
  value: string | number | boolean | (string | number | boolean)[];
  /** How to compare the runtime value against `value`. */
  operator: AttributeOperator;
}

/**
 * A predicate on an object (resource) attribute.
 * Evaluated against the target resource's attributes at policy check time.
 */
export interface ObjectAttribute {
  /** Attribute key (e.g. "sensitivity", "owner", "classification"). */
  key: string;
  /** Expected value or set of values. */
  value: string | number | boolean | (string | number | boolean)[];
  /** How to compare the runtime value against `value`. */
  operator: AttributeOperator;
}

// ---------------------------------------------------------------------------
// PolicyCondition
// ---------------------------------------------------------------------------

/**
 * A structured boolean condition that guards a SecurityPolicy.
 *
 * `expression` is a CEL-like string evaluated by the policy engine at
 * runtime. It has access to `subject`, `object`, `action`, `env`, and
 * `context` namespaces.
 *
 * Example:
 *   "subject.role == 'owner' && object.sensitivityLevel <= 2 && env.hour < 18"
 */
export interface PolicyCondition {
  /**
   * CEL-style boolean expression.
   * Variables: subject.*, object.*, action, env.*, context.*
   */
  expression: string;
  /** Attribute keys that MUST be present for the expression to evaluate. */
  requiredAttributes: string[];
  /**
   * If true the condition depends on runtime context (time, geo, session)
   * and cannot be pre-cached.
   */
  contextual?: boolean;
  /** Human-readable description of what this condition guards. */
  description?: string;
}

// ---------------------------------------------------------------------------
// SecurityPolicy  (SEAgent ABAC)
// ---------------------------------------------------------------------------

/**
 * A full SEAgent ABAC security policy.
 *
 * Captures the five SEAgent dimensions:
 *   - Subject attributes (who is acting)
 *   - Object attributes  (what is being acted upon)
 *   - Action             (what operation)
 *   - Sensitivity / Privacy / Integrity (encoded in subjectAttributes /
 *     objectAttributes and the condition expression)
 *   - Enforcement        (what to do when the policy matches)
 *
 * Policies are evaluated in priority order (lower `version` = older).
 * The policy engine returns the first matching DENY before any ALLOW.
 */
export interface SecurityPolicy {
  /** Unique policy id (UUID v4). */
  id: string;
  /** Human-readable policy name. */
  name: string;
  /** Optional description explaining the business rationale. */
  description?: string;
  /**
   * SEAgent ABAC subject attributes.
   * All predicates must be satisfied for the policy to match.
   */
  subjectAttributes: SubjectAttribute[];
  /**
   * SEAgent ABAC object attributes.
   * All predicates must be satisfied for the policy to match.
   */
  objectAttributes: ObjectAttribute[];
  /**
   * The operation this policy governs.
   * `BROADCAST` implies fan-out to multiple objects simultaneously.
   */
  action: PolicyAction;
  /** Boolean guard evaluated after attribute matching. */
  condition: PolicyCondition;
  /** Enforcement action when policy matches. */
  enforcement: PolicyEnforcement;
  /**
   * The TRiSM threat level associated with a violation of this policy.
   * Used to prioritise alerting and remediation.
   */
  threatLevel: ThreatLevel;
  /** ISO 8601 creation timestamp. */
  createdAt: string;
  /** ISO 8601 last-modified timestamp. */
  updatedAt: string;
  /**
   * Monotonically increasing version number.
   * Used for optimistic concurrency control on policy updates.
   */
  version: number;
  /** Whether this policy is currently active. */
  enabled: boolean;
  /**
   * Optional list of tag strings for grouping / filtering
   * (e.g. ["pii", "gdpr", "hipaa"]).
   */
  tags?: string[];
}

// ---------------------------------------------------------------------------
// PolicyEvaluation  (runtime decision record)
// ---------------------------------------------------------------------------

/**
 * Immutable record of a single policy engine evaluation.
 *
 * Written to the audit log for every policy check. Combined with the
 * triggering `AuditEvent`, these records provide a full decision trail.
 */
export interface PolicyEvaluation {
  /** UUID of this evaluation record. */
  id: string;
  /** The policy that was evaluated. */
  policyId: string;
  /** Name of the evaluated policy (denormalised for log readability). */
  policyName: string;
  /** Id of the acting subject (agent). */
  subjectId: string;
  /** Id of the target object (resource or agent). */
  objectId: string;
  /** The attempted action. */
  action: PolicyAction;
  /** The enforcement decision reached. */
  result: PolicyEnforcement;
  /** Effective threat level at decision time. */
  threatLevel: ThreatLevel;
  /** Condition expressions that evaluated to true. */
  matchedConditions: string[];
  /** Subject attribute values snapshot at evaluation time. */
  subjectSnapshot: Record<string, unknown>;
  /** Object attribute values snapshot at evaluation time. */
  objectSnapshot: Record<string, unknown>;
  /** ISO 8601 evaluation timestamp. */
  timestamp: string;
  /** Wall-clock evaluation duration in milliseconds. */
  durationMs: number;
}

// ---------------------------------------------------------------------------
// ThreatAssessment  (per-request risk summary)
// ---------------------------------------------------------------------------

/**
 * Aggregated threat assessment produced by the policy engine for a single
 * agent request.
 *
 * Combines the worst-case ThreatLevel from all evaluated policies with the
 * set of detected attack vectors.
 */
export interface ThreatAssessment {
  /** UUID of this assessment record. */
  id: string;
  /** The agent being assessed. */
  agentId: string;
  /** Correlation id linking this assessment to the originating request. */
  correlationId: string;
  /** All detected attack vectors in this request. */
  vectors: AttackVector[];
  /** Worst-case threat level across all vectors and policies. */
  threatLevel: ThreatLevel;
  /** Confidence in the assessment, from 0 (none) to 1 (certain). */
  confidence: number;
  /** Human-readable indicators that contributed to the assessment. */
  indicators: string[];
  /** ISO 8601 assessment timestamp. */
  timestamp: string;
  /** Whether automated mitigation was applied (redaction, blocking, etc.). */
  mitigationApplied: boolean;
  /** Description of mitigations applied (populated when `mitigationApplied` is true). */
  mitigationDetails?: string;
  /** Ids of policies that contributed to this assessment. */
  contributingPolicies: string[];
}

// ---------------------------------------------------------------------------
// SensitivityLevel  (data classification)
// ---------------------------------------------------------------------------

/**
 * Data sensitivity / classification levels.
 * Used in ObjectAttributes and PIIPolicy to drive redaction decisions.
 */
export type SensitivityLevel = 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';
