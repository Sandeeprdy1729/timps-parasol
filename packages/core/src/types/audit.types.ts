// TIMPS-Parasol · audit.types.ts
// Append-only audit trail types for the Sentinel logger.
// Every security-relevant action produces an AuditEvent; breach conditions
// are escalated to BreachRecord with full forensic context.

import type { ThreatLevel, AttackVector, PolicyAction } from './security.types.js';

// ---------------------------------------------------------------------------
// AuditCategory  (event taxonomy)
// ---------------------------------------------------------------------------

/**
 * Top-level category for audit events.
 *
 * | Category         | When emitted                                              |
 * |------------------|-----------------------------------------------------------|
 * | AUTH             | Login, token issue/verify, session start/end.             |
 * | POLICY_EVAL      | Every policy engine evaluation (allow or deny).           |
 * | PII_DETECTION    | PII found in prompt or response; redaction applied.        |
 * | AI_CALL          | Outbound request to / response from a Provider.           |
 * | VAULT_ACCESS     | Secret read, write or delete in the Vault.                |
 * | KEY_ROTATION     | Cryptographic key pair generation or rotation.             |
 * | AGENT_ACTION     | Generic agent operation (tool invocation, spawn, etc.).   |
 * | BREACH           | Confirmed or suspected security breach.                   |
 * | CONFIGURATION    | System configuration change (policy add/update/delete).   |
 * | IDENTITY         | Identity verification, anchor creation, credential ops.   |
 * | FLOW_VIOLATION   | Information flow crossed a prohibited boundary.           |
 * | RESOURCE_LIMIT   | Budget threshold exceeded or denied.                     |
 */
export type AuditCategory =
  | 'AUTH'
  | 'POLICY_EVAL'
  | 'PII_DETECTION'
  | 'AI_CALL'
  | 'VAULT_ACCESS'
  | 'KEY_ROTATION'
  | 'AGENT_ACTION'
  | 'BREACH'
  | 'CONFIGURATION'
  | 'IDENTITY'
  | 'FLOW_VIOLATION'
  | 'RESOURCE_LIMIT';

// ---------------------------------------------------------------------------
// AuditEvent
// ---------------------------------------------------------------------------

/**
 * A single immutable record in the append-only audit log.
 *
 * Events are produced by every Parasol layer (AIShield, Perimeter, Identity,
 * Vault, ActionGate, Sentinel) and forwarded to the SentinelLogger.
 *
 * Consumers should never mutate existing events. Corrections are appended as
 * new CORRECTION events referencing the original via `metadata.corrects`.
 */
export interface AuditEvent {
  /** UUID v4. Globally unique across the deployment. */
  id: string;
  /** ISO 8601 UTC timestamp with millisecond precision. */
  timestamp: string;
  /** Coarse category for fast filtering. */
  category: AuditCategory;
  /** Id of the agent that performed (or attempted) the action. */
  agentId: string;
  /** Id of the subject (user / agent) in the originating request, if different from agentId. */
  subjectId?: string;
  /** Id of the resource or agent that was the target of the action. */
  objectId?: string;
  /** Human-readable description of the operation (e.g. "VAULT_READ", "POLICY_DENY"). */
  action: string;
  /** Outcome of the operation. */
  result: 'SUCCESS' | 'FAILURE' | 'BLOCKED' | 'REQUIRES_CONFIRMATION';
  /** TRiSM threat level associated with this event. */
  threatLevel: ThreatLevel;
  /** Originating IP address. */
  ip?: string;
  /** SHA-256 hash of the User-Agent string (never the raw UA). */
  userAgentHash?: string;
  /** Correlation id linking this event to the parent request. */
  correlationId?: string;
  /** Arbitrary structured metadata. Must not contain raw PII values. */
  metadata: Record<string, unknown>;
  /** Wall-clock duration of the operation in milliseconds. */
  durationMs?: number;
  /** Layer that produced this event (e.g. "AIShield", "Perimeter", "Vault"). */
  layer?: string;
  /** Policy id that triggered the event, if applicable. */
  policyId?: string;
}

// ---------------------------------------------------------------------------
// AuditLog  (per-agent log view)
// ---------------------------------------------------------------------------

/**
 * A logical view of all audit events for a single agent.
 *
 * The `AuditLog` is a derived / cached view and is never the authoritative
 * store. The Sentinel is the authoritative source.
 */
export interface AuditLog {
  /** UUID of the log view. */
  id: string;
  /** Agent this log belongs to. */
  agentId: string;
  /** Ordered slice of audit events (oldest first). */
  events: AuditEvent[];
  /** ISO 8601 timestamp of the first event. */
  createdAt: string;
  /** ISO 8601 timestamp of the most recent event. */
  updatedAt: string;
  /** Total number of events in the log (may exceed `events.length` if paginated). */
  totalEvents: number;
  /** Total number of confirmed breach events in the log. */
  breachCount: number;
  /** Summary count by category for dashboard display. */
  categoryCounts: Partial<Record<AuditCategory, number>>;
  /** Summary count by result type. */
  resultCounts: Partial<Record<AuditEvent['result'], number>>;
}

// ---------------------------------------------------------------------------
// BreachRecord
// ---------------------------------------------------------------------------

/**
 * A detailed forensic record created when an attack or serious policy
 * violation is confirmed.
 *
 * BreachRecords are created by the Sentinel's breach-detection routines and
 * trigger owner notifications via the configured NotificationChannels.
 */
export interface BreachRecord {
  /** UUID v4. */
  id: string;
  /** ISO 8601 UTC timestamp when the breach was detected. */
  timestamp: string;
  /** Id of the agent involved in (or targeted by) the breach. */
  agentId: string;
  /** Primary attack vector classified by the Sentinel. */
  attackVector: AttackVector;
  /** All attack vectors observed in this incident. */
  allVectors: AttackVector[];
  /** TRiSM threat level of the breach. */
  threatLevel: ThreatLevel;
  /** Human-readable description of what happened. */
  description: string;
  /**
   * Ids of resources (vault secrets, memory stores, files) that were
   * accessed or potentially exfiltrated.
   */
  affectedResources: string[];
  /** Ids of policies that were violated or that triggered the detection. */
  triggeredPolicies: string[];
  /**
   * Recommended or already-applied mitigation steps.
   * Ordered from most to least impactful.
   */
  mitigationSteps: string[];
  /** Whether the breach has been resolved / closed. */
  resolved: boolean;
  /** ISO 8601 timestamp when the breach was resolved. */
  resolvedAt?: string;
  /** Id of the agent or operator that resolved the breach. */
  resolvedBy?: string;
  /** Post-mortem notes added after resolution. */
  resolution?: string;
  /** Audit events that constitute the forensic evidence for this breach. */
  evidence: AuditEvent[];
  /** Estimated data sensitivity of the potentially exposed data. */
  impactSeverity: 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';
  /** Whether owner notifications have been sent. */
  notificationSent: boolean;
  /** ISO 8601 timestamp of owner notification (null if not yet sent). */
  notifiedAt?: string;
}

// ---------------------------------------------------------------------------
// AuditQuery  (filtering)
// ---------------------------------------------------------------------------

/**
 * Parameters for querying the audit log.
 *
 * All fields are optional and combined with AND semantics.
 */
export interface AuditQuery {
  /** Filter by agent id. */
  agentId?: string;
  /** Filter by audit category. */
  category?: AuditCategory;
  /** ISO 8601 start timestamp (inclusive). */
  from?: string;
  /** ISO 8601 end timestamp (inclusive). */
  to?: string;
  /** Filter by action string (exact match). */
  action?: PolicyAction | string;
  /** Filter by result. */
  result?: AuditEvent['result'];
  /** Only return events at or above this threat level. */
  minThreatLevel?: ThreatLevel;
  /** Filter by policy id. */
  policyId?: string;
  /** Filter by correlation id. */
  correlationId?: string;
  /** Filter by layer. */
  layer?: string;
  /** Maximum number of events to return (default: 100, max: 1000). */
  limit?: number;
  /** Offset for pagination. */
  offset?: number;
  /** Field to sort by (default: "timestamp"). */
  sortBy?: keyof AuditEvent;
  /** Sort direction (default: "DESC"). */
  sortDir?: 'ASC' | 'DESC';
}

// ---------------------------------------------------------------------------
// AuditExport
// ---------------------------------------------------------------------------

/**
 * A signed, tamper-evident export of a set of audit events.
 *
 * Used for regulatory reporting and external SIEM ingestion.
 */
export interface AuditExport {
  /** UUID of this export operation. */
  id: string;
  /** ISO 8601 timestamp when the export was generated. */
  generatedAt: string;
  /** Id of the agent that requested the export. */
  requestedBy: string;
  /** The query used to produce this export. */
  query: AuditQuery;
  /** Number of events included. */
  eventCount: number;
  /** JSON-serialised events. */
  payload: string;
  /**
   * Ed25519 signature over `payload` using the Sentinel's signing key.
   * Verifiable with `utils/crypto.ts#verifyEd25519`.
   */
  signature: string;
  /** Public key (PEM) used to sign this export. */
  signingPublicKey: string;
}
