// TIMPS-Parasol · agent.types.ts
// Defines the Agent hierarchy: Owner, NonOwner, Provider, and supporting shapes.
// All agent interactions flow through these contracts.

// ---------------------------------------------------------------------------
// Role
// ---------------------------------------------------------------------------

/**
 * Coarse-grained role for an agent within the Parasol trust model.
 *
 * - `owner`      – the human or org that provisioned the deployment; highest trust.
 * - `non-owner`  – a delegated user or downstream agent; trust is scoped.
 * - `provider`   – an upstream model / API provider; externally managed identity.
 * - `auditor`    – read-only compliance observer; can query but cannot act.
 * - `admin`      – system administrator; can mutate configuration.
 */
export type Role = 'owner' | 'non-owner' | 'provider' | 'auditor' | 'admin';

// ---------------------------------------------------------------------------
// Agent lifecycle
// ---------------------------------------------------------------------------

/**
 * Operational status of an agent instance.
 *
 * Transitions:
 *   active → paused    (HIGH threat detected, awaiting owner confirmation)
 *   active → blocked   (CRITICAL threat; automatic; requires manual unblock)
 *   any    → terminated (explicit shutdown or severe policy violation)
 */
export type AgentStatus = 'active' | 'paused' | 'blocked' | 'terminated';

// ---------------------------------------------------------------------------
// Capabilities (fine-grained permission tokens)
// ---------------------------------------------------------------------------

/**
 * Granular capability tokens granted to an agent.
 * Used during ABAC policy evaluation to constrain what the agent may do.
 *
 * | Token               | Description                                         |
 * |---------------------|-----------------------------------------------------|
 * | READ_MEMORY         | Read from the agent's own memory or shared stores.  |
 * | WRITE_MEMORY        | Persist data to memory / knowledge stores.          |
 * | INVOKE_TOOL         | Execute registered tools or function calls.         |
 * | SPAWN_SUBAGENT      | Instantiate child agents.                           |
 * | CALL_EXTERNAL_API   | Make outbound HTTP requests to third-party APIs.    |
 * | ACCESS_VAULT        | Decrypt secrets from the Parasol Vault.             |
 * | BROADCAST_MESSAGE   | Send messages to multiple recipients simultaneously.|
 * | MODIFY_POLICY       | Create or mutate SecurityPolicy records.            |
 * | ROTATE_KEYS         | Initiate cryptographic key rotation.                |
 * | VIEW_AUDIT_LOG      | Read the append-only audit trail.                   |
 * | MANAGE_IDENTITIES   | Create, revoke or update VerifiedIdentity records.  |
 * | EXPORT_DATA         | Extract data outside the agent's isolation boundary.|
 */
export type AgentCapability =
  | 'READ_MEMORY'
  | 'WRITE_MEMORY'
  | 'INVOKE_TOOL'
  | 'SPAWN_SUBAGENT'
  | 'CALL_EXTERNAL_API'
  | 'ACCESS_VAULT'
  | 'BROADCAST_MESSAGE'
  | 'MODIFY_POLICY'
  | 'ROTATE_KEYS'
  | 'VIEW_AUDIT_LOG'
  | 'MANAGE_IDENTITIES'
  | 'EXPORT_DATA';

// ---------------------------------------------------------------------------
// Notification channels
// ---------------------------------------------------------------------------

/** Delivery channel for owner alerts (breach, HIGH/CRITICAL threat, etc.). */
export interface NotificationChannel {
  /** Unique channel id within the owner's profile. */
  id: string;
  /** Transport mechanism. */
  type: 'email' | 'webhook' | 'sms' | 'push' | 'slack' | 'pagerduty';
  /** Channel-specific destination (email address, URL, phone number …). */
  target: string;
  /** Whether this channel is currently active. */
  enabled: boolean;
  /** Minimum ThreatLevel that triggers a notification via this channel. */
  minThreatLevel: 0 | 1 | 2 | 3 | 4;
}

// ---------------------------------------------------------------------------
// Subscription / compliance
// ---------------------------------------------------------------------------

export type SubscriptionTier = 'free' | 'pro' | 'enterprise';

export type ComplianceLevel = 'basic' | 'soc2' | 'hipaa' | 'pci' | 'iso27001';

// ---------------------------------------------------------------------------
// Core Agent interface
// ---------------------------------------------------------------------------

/**
 * Base shape shared by all agent variants.
 *
 * Identity anchoring, capability tokens and trust scores are the three primary
 * axes used by Parasol's policy engine to make allow/deny decisions.
 */
export interface Agent {
  /** Globally unique agent id (UUID v4). */
  id: string;
  /** Human-readable display name. */
  name: string;
  /** Coarse role within the trust hierarchy. */
  role: Role;
  /** Fine-grained capability tokens granted to this agent. */
  capabilities: AgentCapability[];
  /**
   * Composite trust score in [0, 1].
   * Derived by `utils/scoring.ts#computeTrustScore`.
   * 0 = completely untrusted, 1 = fully trusted.
   */
  trustScore: number;
  /** Current lifecycle status. */
  status: AgentStatus;
  /** Id of the Owner agent that provisioned this agent. */
  ownerId: string;
  /**
   * Id of the upstream AI Provider (if any).
   * Populated only for model-backed agents.
   */
  providerId?: string;
  /** Arbitrary extension metadata. Must not contain raw PII. */
  metadata: Record<string, unknown>;
  /** ISO 8601 creation timestamp. */
  createdAt: string;
  /** ISO 8601 last-update timestamp. */
  updatedAt: string;
}

// ---------------------------------------------------------------------------
// Owner
// ---------------------------------------------------------------------------

/**
 * Owner agent — highest trust; provisioned the deployment.
 *
 * Owners receive real-time breach alerts, can unblock paused agents, approve
 * REQUIRE_CONFIRMATION policy actions, and manage subscription/compliance.
 */
export interface Owner extends Agent {
  role: 'owner';
  /** Determines available feature set and rate limits. */
  subscriptionTier: SubscriptionTier;
  /** Channels through which the owner receives security notifications. */
  notificationChannels: NotificationChannel[];
  /** Compliance frameworks the owner has attested to. */
  complianceCertifications: ComplianceLevel[];
  /** Whether the owner has enabled multi-factor authentication. */
  mfaEnabled: boolean;
}

// ---------------------------------------------------------------------------
// NonOwner
// ---------------------------------------------------------------------------

/**
 * Non-owner agent — delegated user or downstream sub-agent.
 *
 * Trust is bounded by the delegating owner and further constrained by the
 * explicit `permissions` list. NonOwner agents cannot modify policies or
 * perform key rotation unless explicitly granted.
 */
export interface NonOwner extends Agent {
  role: 'non-owner';
  /** Id of the Owner that delegated authority to this agent. */
  delegatedBy: string;
  /** Explicit list of policy IDs or action tokens this agent may exercise. */
  permissions: string[];
  /** ISO 8601 timestamp when delegation expires (optional). */
  delegationExpiresAt?: string;
  /** Whether delegation is revocable by the owner at any time. */
  revocable: boolean;
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

/**
 * Provider agent — an upstream AI model or API provider.
 *
 * Providers are treated as semi-trusted external principals. All data sent to
 * a Provider is screened by AIShield (PII redaction + injection detection)
 * before transmission, and all Provider responses are scanned on return.
 */
export interface Provider extends Agent {
  role: 'provider';
  /** Model identifier (e.g. "gpt-4o", "claude-opus-4", "gemini-2-flash"). */
  modelId: string;
  /** Base URL for API calls to this provider. */
  apiEndpoint: string;
  /** Maximum requests per minute allowed by the provider's rate limit. */
  rateLimitRpm: number;
  /** Highest compliance certification attested by this provider. */
  complianceLevel: ComplianceLevel;
  /**
   * Whether to apply strict PII redaction before sending prompts to this
   * provider (default: true for all non-internal providers).
   */
  requiresPIIRedaction: boolean;
  /** Whether the provider supports confidential computing / TEE execution. */
  supportsConfidentialCompute: boolean;
}

// ---------------------------------------------------------------------------
// AgentSession
// ---------------------------------------------------------------------------

/**
 * A bounded execution session for an agent.
 *
 * Sessions track activity within a time window and are used by the Sentinel
 * to detect anomalous behaviour patterns.
 */
export interface AgentSession {
  /** Unique session id (UUID v4). */
  id: string;
  /** The agent this session belongs to. */
  agentId: string;
  /** IP address of the originating request. */
  ip: string;
  /** SHA-256 hash of the User-Agent string. */
  userAgentHash: string;
  /** ISO 8601 session start timestamp. */
  startedAt: string;
  /** ISO 8601 session end timestamp (null while active). */
  endedAt?: string;
  /** Number of actions performed in this session. */
  actionCount: number;
  /** Whether this session was flagged for suspicious behaviour. */
  flagged: boolean;
  /** Reason for flagging (populated only when `flagged` is true). */
  flagReason?: string;
}

// ---------------------------------------------------------------------------
// AgentContext (runtime)
// ---------------------------------------------------------------------------

/**
 * Runtime context injected into every policy evaluation and audit event.
 *
 * Assembled once per request by the API middleware and passed through the
 * entire request lifecycle to avoid re-deriving identity on each call.
 */
export interface AgentContext {
  /** The acting agent. */
  agent: Agent;
  /** Current active session. */
  session: AgentSession;
  /** Resolved capabilities for the current request (may be subset of agent.capabilities). */
  effectiveCapabilities: AgentCapability[];
  /** ISO 8601 timestamp of context creation. */
  timestamp: string;
  /** Unique correlation id for distributed tracing. */
  correlationId: string;
}
