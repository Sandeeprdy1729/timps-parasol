// TIMPS-Parasol · flow.types.ts
// Information-flow tracking types for the Parasol perimeter.
// Models data movement between agents and resources as a directed labelled
// graph; policies are enforced on every edge traversal.

import type { ThreatLevel } from './security.types.js';
import type { PIIType } from './pii.types.js';

// ---------------------------------------------------------------------------
// FlowLabel  (data-classification labels on edges)
// ---------------------------------------------------------------------------

/**
 * Classification labels that may be attached to an information-flow edge.
 * Multiple labels can be combined (e.g. PII_BEARING + ENCRYPTED).
 *
 * | Label            | Meaning                                                |
 * |------------------|--------------------------------------------------------|
 * | TRUSTED          | Source is a verified, high-trust principal.            |
 * | UNTRUSTED        | Source is external or unverified.                      |
 * | CONFIDENTIAL     | Data classified confidential by the owner.             |
 * | PII_BEARING      | Data contains or may contain PII.                      |
 * | POLICY_CONTROLLED| One or more SecurityPolicies govern this flow.         |
 * | ENCRYPTED        | Data is encrypted end-to-end in transit.               |
 * | REDACTED         | PII has been redacted before transmission.             |
 * | AUDIT_REQUIRED   | Flow must produce an audit event regardless of result. |
 * | CROSS_BOUNDARY   | Flow crosses a trust-domain boundary.                  |
 */
export type FlowLabel =
  | 'TRUSTED'
  | 'UNTRUSTED'
  | 'CONFIDENTIAL'
  | 'PII_BEARING'
  | 'POLICY_CONTROLLED'
  | 'ENCRYPTED'
  | 'REDACTED'
  | 'AUDIT_REQUIRED'
  | 'CROSS_BOUNDARY';

// ---------------------------------------------------------------------------
// FlowNodeType
// ---------------------------------------------------------------------------

/**
 * The category of a node in the flow graph.
 *
 * | Type     | Examples                                         |
 * |----------|--------------------------------------------------|
 * | AGENT    | Owner, NonOwner, Provider agents                 |
 * | RESOURCE | Files, databases, memory stores, APIs            |
 * | EXTERNAL | Third-party endpoints outside the trust perimeter|
 * | VAULT    | Parasol Vault (encrypted secrets store)          |
 * | MODEL    | AI model endpoint (Provider API)                 |
 * | GATEWAY  | API gateway, message broker, CDN                 |
 */
export type FlowNodeType =
  | 'AGENT'
  | 'RESOURCE'
  | 'EXTERNAL'
  | 'VAULT'
  | 'MODEL'
  | 'GATEWAY';

// ---------------------------------------------------------------------------
// InformationFlowEdge  (directed edge in the flow graph)
// ---------------------------------------------------------------------------

/**
 * A directed, labelled edge representing one information-flow event.
 *
 * Every edge is immutable once created; subsequent flows generate new edges.
 * This gives a full temporal record of how data moved through the system.
 */
export interface InformationFlowEdge {
  /** UUID v4. */
  id: string;
  /** Id of the graph this edge belongs to. */
  graphId: string;
  /** Id of the source node (agent or resource emitting data). */
  sourceId: string;
  /** Id of the target node (agent or resource receiving data). */
  targetId: string;
  /** Classification labels applied to the data in transit. */
  dataClassification: FlowLabel[];
  /** PII types present in the data, if any were detected. */
  piiTypes: PIIType[];
  /** Threat level associated with this flow. */
  threatLevel: ThreatLevel;
  /** Whether the data was encrypted during transit. */
  encryptedInTransit: boolean;
  /** Ids of SecurityPolicies that were evaluated for this edge. */
  policyIds: string[];
  /** ISO 8601 timestamp when the flow occurred. */
  timestamp: string;
  /**
   * Whether the flow was ultimately permitted.
   * False means the edge represents a blocked / denied flow.
   */
  allowed: boolean;
  /** Reason for denial (populated when `allowed` is false). */
  denyReason?: string;
  /** Wall-clock duration of the data transfer in milliseconds. */
  durationMs?: number;
  /** Approximate byte size of the data in transit. */
  byteSize?: number;
  /** Correlation id linking this edge to the originating request. */
  correlationId?: string;
}

// ---------------------------------------------------------------------------
// FlowNode
// ---------------------------------------------------------------------------

/**
 * A node in the information-flow graph.
 *
 * Nodes are reference counted: each edge add/remove updates the
 * `inboundEdges` / `outboundEdges` edge-id sets. The graph utilities in
 * `utils/graph.ts` maintain these sets automatically.
 */
export interface FlowNode {
  /** The agent or resource id this node represents. */
  id: string;
  /** Display label for visualisation. */
  label: string;
  /** Category of this node. */
  type: FlowNodeType;
  /** Trust level of this node (derived from its TrustScore or policy). */
  trustLevel: ThreatLevel;
  /** Ids of inbound edges (flows arriving at this node). */
  inboundEdges: string[];
  /** Ids of outbound edges (flows departing from this node). */
  outboundEdges: string[];
  /** Whether this node is currently active / reachable. */
  active: boolean;
  /** ISO 8601 timestamp when this node was added to the graph. */
  createdAt: string;
}

// ---------------------------------------------------------------------------
// FlowGraph
// ---------------------------------------------------------------------------

/**
 * The full information-flow graph for a deployment or session.
 *
 * Nodes and edges are stored in `Map`s for O(1) lookup by id.
 * Use `utils/graph.ts` for traversal, path finding and cycle detection.
 */
export interface FlowGraph {
  /** UUID v4 identifying this graph instance. */
  id: string;
  /** Optional human-readable label (e.g. "session-xyz" or "deployment-prod"). */
  label?: string;
  /** All nodes keyed by node id. */
  nodes: Map<string, FlowNode>;
  /** All edges keyed by edge id. */
  edges: Map<string, InformationFlowEdge>;
  /** ISO 8601 timestamp when the graph was initialised. */
  createdAt: string;
  /** ISO 8601 timestamp of the most recent mutation. */
  updatedAt: string;
}

// ---------------------------------------------------------------------------
// FlowPath  (result of path-finding in the graph)
// ---------------------------------------------------------------------------

/**
 * A concrete path from `sourceId` to `targetId` through the flow graph.
 *
 * Returned by `utils/graph.ts#findAllPaths` and used by the policy engine to
 * detect transitive information-flow violations.
 */
export interface FlowPath {
  /** UUID for this path instance. */
  id: string;
  /** Id of the source node. */
  sourceId: string;
  /** Id of the target node. */
  targetId: string;
  /** Ordered list of node ids from source to target (inclusive). */
  hops: string[];
  /** Ordered list of edge ids traversed along this path. */
  edges: string[];
  /** Worst-case threat level across all edges on this path. */
  totalThreatLevel: ThreatLevel;
  /** Whether any edge on this path is PII_BEARING. */
  hasPII: boolean;
  /** Whether all edges on this path are permitted by their policies. */
  compliant: boolean;
  /** Ids of policies violated by one or more edges on this path. */
  violatedPolicies: string[];
  /** Total hop count (number of intermediate nodes). */
  hopCount: number;
}

// ---------------------------------------------------------------------------
// FlowViolation
// ---------------------------------------------------------------------------

/**
 * A single policy violation detected on an information-flow edge.
 *
 * Generated by the flow-policy evaluator and appended to the audit log.
 * Multiple violations may exist for a single edge (one per violated policy).
 */
export interface FlowViolation {
  /** UUID v4. */
  id: string;
  /** Id of the FlowGraph this violation belongs to. */
  graphId: string;
  /** Id of the edge on which the violation was detected. */
  edgeId: string;
  /** Id of the policy that was violated. */
  policyId: string;
  /** Human-readable explanation of the violation. */
  reason: string;
  /** Threat level of the violated policy. */
  threatLevel: ThreatLevel;
  /** ISO 8601 detection timestamp. */
  timestamp: string;
  /** Whether automated remediation was applied. */
  remediated: boolean;
  /** Description of the remediation (if applied). */
  remediationDetails?: string;
}

// ---------------------------------------------------------------------------
// FlowSnapshot  (point-in-time export)
// ---------------------------------------------------------------------------

/**
 * A serialisable snapshot of the flow graph at a specific instant.
 *
 * Used for cross-session persistence and compliance reporting.
 * The `FlowGraph` type uses `Map` objects which are not directly JSON-
 * serialisable; this snapshot converts them to plain arrays.
 */
export interface FlowSnapshot {
  /** UUID of the snapshot. */
  id: string;
  /** Id of the source FlowGraph. */
  graphId: string;
  /** ISO 8601 snapshot timestamp. */
  snapshotAt: string;
  /** Flat array of all nodes. */
  nodes: FlowNode[];
  /** Flat array of all edges. */
  edges: InformationFlowEdge[];
  /** All violations detected since the previous snapshot. */
  violations: FlowViolation[];
  /** Total number of allowed flows. */
  allowedFlows: number;
  /** Total number of blocked flows. */
  blockedFlows: number;
}
