// TIMPS-Parasol · utils/graph.ts
// Directed graph primitives for information-flow tracking.
//
// Used by:
//   packages/sdk/src/perimeter.ts   — builds the flow graph per session
//   api/src/routes/vault.ts         — tracks vault access flows
//   dashboard/src/pages/Vault.tsx   — visualises flow graph snapshots
//
// Design goals:
//   • O(1) node/edge lookup by id
//   • Incremental edge addition (append-only; edges are never removed)
//   • Cycle detection for detecting circular information flows
//   • Path finding for transitive policy-violation detection
//   • Full snapshot serialisation for cross-session persistence

import type { FlowGraph, FlowNode, InformationFlowEdge, FlowPath, FlowNodeType } from '../types/flow.types.js';
import type { FlowViolation } from '../types/flow.types.js';
import { ThreatLevel } from '../types/security.types.js';
import { generateSecureUUID } from './crypto.js';

// ---------------------------------------------------------------------------
// Graph construction
// ---------------------------------------------------------------------------

/**
 * Create an empty FlowGraph.
 */
export function createFlowGraph(label?: string): FlowGraph {
  return {
    id:        generateSecureUUID(),
    label,
    nodes:     new Map(),
    edges:     new Map(),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
}

/**
 * Add a node to the graph. Idempotent — if a node with the same id already
 * exists, returns the existing node without modification.
 */
export function addNode(
  graph: FlowGraph,
  nodeId: string,
  label: string,
  type: FlowNodeType,
  trustLevel: ThreatLevel = ThreatLevel.NONE,
): FlowNode {
  if (graph.nodes.has(nodeId)) {
    return graph.nodes.get(nodeId)!;
  }
  const node: FlowNode = {
    id:            nodeId,
    label,
    type,
    trustLevel,
    inboundEdges:  [],
    outboundEdges: [],
    active:        true,
    createdAt:     new Date().toISOString(),
  };
  graph.nodes.set(nodeId, node);
  graph.updatedAt = new Date().toISOString();
  return node;
}

/**
 * Add a directed edge to the graph, automatically updating the source and
 * target nodes' edge-id lists.
 *
 * Ensures both source and target nodes exist (auto-creates RESOURCE nodes if
 * not already present).
 */
export function addEdge(
  graph: FlowGraph,
  edge: InformationFlowEdge,
): InformationFlowEdge {
  // Auto-create nodes if they don't exist
  if (!graph.nodes.has(edge.sourceId)) {
    addNode(graph, edge.sourceId, edge.sourceId, 'RESOURCE');
  }
  if (!graph.nodes.has(edge.targetId)) {
    addNode(graph, edge.targetId, edge.targetId, 'RESOURCE');
  }

  graph.edges.set(edge.id, edge);

  const source = graph.nodes.get(edge.sourceId)!;
  const target = graph.nodes.get(edge.targetId)!;
  source.outboundEdges.push(edge.id);
  target.inboundEdges.push(edge.id);

  graph.updatedAt = new Date().toISOString();
  return edge;
}

/**
 * Mark a node as inactive (soft delete). Edges referencing it are retained.
 */
export function deactivateNode(graph: FlowGraph, nodeId: string): boolean {
  const node = graph.nodes.get(nodeId);
  if (!node) return false;
  node.active = false;
  graph.updatedAt = new Date().toISOString();
  return true;
}

// ---------------------------------------------------------------------------
// Traversal — BFS
// ---------------------------------------------------------------------------

/**
 * Return all node ids reachable from `startId` via outbound edges (BFS).
 * Includes `startId` itself.
 */
export function reachableFrom(graph: FlowGraph, startId: string): Set<string> {
  const visited = new Set<string>();
  const queue   = [startId];

  while (queue.length > 0) {
    const nodeId = queue.shift()!;
    if (visited.has(nodeId)) continue;
    visited.add(nodeId);

    const node = graph.nodes.get(nodeId);
    if (!node) continue;

    for (const edgeId of node.outboundEdges) {
      const edge = graph.edges.get(edgeId);
      if (edge && !visited.has(edge.targetId)) {
        queue.push(edge.targetId);
      }
    }
  }
  return visited;
}

/**
 * Return all node ids from which `targetId` is reachable via outbound edges
 * (reverse BFS — walk inbound edges backwards).
 * Includes `targetId` itself.
 */
export function ancestorsOf(graph: FlowGraph, targetId: string): Set<string> {
  const visited = new Set<string>();
  const queue   = [targetId];

  while (queue.length > 0) {
    const nodeId = queue.shift()!;
    if (visited.has(nodeId)) continue;
    visited.add(nodeId);

    const node = graph.nodes.get(nodeId);
    if (!node) continue;

    for (const edgeId of node.inboundEdges) {
      const edge = graph.edges.get(edgeId);
      if (edge && !visited.has(edge.sourceId)) {
        queue.push(edge.sourceId);
      }
    }
  }
  return visited;
}

// ---------------------------------------------------------------------------
// Path finding
// ---------------------------------------------------------------------------

/**
 * Find all simple paths from `sourceId` to `targetId`.
 *
 * Returns up to `maxPaths` results (default: 10) to avoid combinatorial
 * explosion on dense graphs.
 *
 * @param graph     - The flow graph.
 * @param sourceId  - Id of the start node.
 * @param targetId  - Id of the end node.
 * @param maxPaths  - Maximum number of paths to return (default: 10).
 */
export function findAllPaths(
  graph: FlowGraph,
  sourceId: string,
  targetId: string,
  maxPaths = 10,
): FlowPath[] {
  const results: FlowPath[] = [];

  function dfs(
    currentId: string,
    visitedNodes: Set<string>,
    pathNodeIds: string[],
    pathEdgeIds: string[],
    worstThreat: ThreatLevel,
    hasPII: boolean,
  ): void {
    if (results.length >= maxPaths) return;

    if (currentId === targetId && pathNodeIds.length > 1) {
      // Build a FlowPath from the current state
      const violatedPolicies: string[] = [];
      let compliant = true;

      for (const edgeId of pathEdgeIds) {
        const edge = graph.edges.get(edgeId);
        if (edge && !edge.allowed) {
          compliant = false;
          violatedPolicies.push(...edge.policyIds);
        }
      }

      results.push({
        id:               generateSecureUUID(),
        sourceId,
        targetId,
        hops:             [...pathNodeIds],
        edges:            [...pathEdgeIds],
        totalThreatLevel: worstThreat,
        hasPII,
        compliant,
        violatedPolicies: [...new Set(violatedPolicies)],
        hopCount:         pathNodeIds.length - 2, // exclude source and target
      });
      return;
    }

    const node = graph.nodes.get(currentId);
    if (!node) return;

    for (const edgeId of node.outboundEdges) {
      const edge = graph.edges.get(edgeId);
      if (!edge) continue;
      const nextId = edge.targetId;
      if (visitedNodes.has(nextId)) continue; // no revisiting (simple paths only)

      const nextThreat  = Math.max(worstThreat, edge.threatLevel) as ThreatLevel;
      const nextHasPII  = hasPII || edge.piiTypes.length > 0;

      visitedNodes.add(nextId);
      pathNodeIds.push(nextId);
      pathEdgeIds.push(edgeId);

      dfs(nextId, visitedNodes, pathNodeIds, pathEdgeIds, nextThreat, nextHasPII);

      visitedNodes.delete(nextId);
      pathNodeIds.pop();
      pathEdgeIds.pop();
    }
  }

  if (!graph.nodes.has(sourceId) || !graph.nodes.has(targetId)) {
    return [];
  }

  dfs(
    sourceId,
    new Set([sourceId]),
    [sourceId],
    [],
    ThreatLevel.NONE,
    false,
  );

  return results;
}

// ---------------------------------------------------------------------------
// Cycle detection
// ---------------------------------------------------------------------------

/**
 * Detect cycles in the flow graph using DFS coloring.
 *
 * @returns Array of cycle paths (each as an ordered list of node ids).
 */
export function detectCycles(graph: FlowGraph): string[][] {
  const cycles: string[][] = [];
  const color = new Map<string, 'WHITE' | 'GRAY' | 'BLACK'>();

  for (const nodeId of graph.nodes.keys()) {
    color.set(nodeId, 'WHITE');
  }

  function dfs(nodeId: string, stack: string[]): void {
    color.set(nodeId, 'GRAY');
    stack.push(nodeId);

    const node = graph.nodes.get(nodeId);
    if (!node) {
      stack.pop();
      color.set(nodeId, 'BLACK');
      return;
    }

    for (const edgeId of node.outboundEdges) {
      const edge = graph.edges.get(edgeId);
      if (!edge) continue;
      const nextId = edge.targetId;
      const nextColor = color.get(nextId);

      if (nextColor === 'GRAY') {
        // Found a back edge — record the cycle
        const cycleStart = stack.indexOf(nextId);
        cycles.push(stack.slice(cycleStart));
      } else if (nextColor === 'WHITE') {
        dfs(nextId, stack);
      }
    }

    stack.pop();
    color.set(nodeId, 'BLACK');
  }

  for (const nodeId of graph.nodes.keys()) {
    if (color.get(nodeId) === 'WHITE') {
      dfs(nodeId, []);
    }
  }

  return cycles;
}

// ---------------------------------------------------------------------------
// Shortest path  (Dijkstra — by hop count)
// ---------------------------------------------------------------------------

/**
 * Find the shortest path (by hop count) between two nodes using BFS.
 * Returns null if no path exists.
 */
export function shortestPath(
  graph: FlowGraph,
  sourceId: string,
  targetId: string,
): FlowPath | null {
  if (!graph.nodes.has(sourceId) || !graph.nodes.has(targetId)) return null;
  if (sourceId === targetId) return null;

  const visited  = new Set<string>([sourceId]);
  const queue: Array<{ nodeId: string; pathNodes: string[]; pathEdges: string[] }> = [
    { nodeId: sourceId, pathNodes: [sourceId], pathEdges: [] },
  ];

  while (queue.length > 0) {
    const { nodeId, pathNodes, pathEdges } = queue.shift()!;
    const node = graph.nodes.get(nodeId);
    if (!node) continue;

    for (const edgeId of node.outboundEdges) {
      const edge = graph.edges.get(edgeId);
      if (!edge) continue;
      const nextId = edge.targetId;
      if (visited.has(nextId)) continue;
      visited.add(nextId);

      const newPathNodes = [...pathNodes, nextId];
      const newPathEdges = [...pathEdges, edgeId];

      if (nextId === targetId) {
        const worstThreat = newPathEdges.reduce<ThreatLevel>((max, eid) => {
          const e = graph.edges.get(eid);
          return e ? Math.max(max, e.threatLevel) as ThreatLevel : max;
        }, ThreatLevel.NONE);
        const hasPII = newPathEdges.some((eid) => {
          const e = graph.edges.get(eid);
          return e ? e.piiTypes.length > 0 : false;
        });
        const violatedPolicies = newPathEdges.flatMap((eid) => {
          const e = graph.edges.get(eid);
          return e && !e.allowed ? e.policyIds : [];
        });

        return {
          id:               generateSecureUUID(),
          sourceId,
          targetId,
          hops:             newPathNodes,
          edges:            newPathEdges,
          totalThreatLevel: worstThreat,
          hasPII,
          compliant:        violatedPolicies.length === 0,
          violatedPolicies: [...new Set(violatedPolicies)],
          hopCount:         newPathNodes.length - 2,
        };
      }

      queue.push({ nodeId: nextId, pathNodes: newPathNodes, pathEdges: newPathEdges });
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// Violation detection
// ---------------------------------------------------------------------------

/**
 * Scan all edges in the graph and return FlowViolation records for every
 * edge where `allowed === false`.
 */
export function collectViolations(graph: FlowGraph): FlowViolation[] {
  const violations: FlowViolation[] = [];
  for (const edge of graph.edges.values()) {
    if (!edge.allowed) {
      for (const policyId of edge.policyIds) {
        violations.push({
          id:               generateSecureUUID(),
          graphId:          graph.id,
          edgeId:           edge.id,
          policyId,
          reason:           edge.denyReason ?? 'Policy denied this information flow',
          threatLevel:      edge.threatLevel,
          timestamp:        edge.timestamp,
          remediated:       false,
        });
      }
    }
  }
  return violations;
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

export interface GraphStats {
  nodeCount: number;
  activeNodeCount: number;
  edgeCount: number;
  allowedEdges: number;
  blockedEdges: number;
  piiEdges: number;
  hasCycles: boolean;
  cycleCount: number;
  maxThreatLevel: ThreatLevel;
}

/**
 * Compute summary statistics over a flow graph.
 */
export function graphStats(graph: FlowGraph): GraphStats {
  let allowedEdges  = 0;
  let blockedEdges  = 0;
  let piiEdges      = 0;
  let maxThreat     = ThreatLevel.NONE;

  for (const edge of graph.edges.values()) {
    if (edge.allowed) allowedEdges++; else blockedEdges++;
    if (edge.piiTypes.length > 0) piiEdges++;
    if (edge.threatLevel > maxThreat) maxThreat = edge.threatLevel;
  }

  const cycles = detectCycles(graph);

  return {
    nodeCount:       graph.nodes.size,
    activeNodeCount: [...graph.nodes.values()].filter((n) => n.active).length,
    edgeCount:       graph.edges.size,
    allowedEdges,
    blockedEdges,
    piiEdges,
    hasCycles:       cycles.length > 0,
    cycleCount:      cycles.length,
    maxThreatLevel:  maxThreat,
  };
}
