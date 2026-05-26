/**
 * Template (grouped-by-type) attack-path graph.
 *
 * The default visualization is a compact "structure of the attack" graph: one
 * node per resource *type* (e.g. "AWS Role", "EC2 Instance") plus a terminal
 * Outcome node, connected left-to-right in the direction of the attack. Each
 * type node can be expanded to reveal the concrete resources it represents.
 *
 * This keeps the first read of the graph easy (the shape of the attack) and
 * makes the concrete resources available on demand. Account/root nodes are
 * never included (already stripped by the API; filtered defensively here), and
 * findings are intentionally left out of this structural view.
 */

import type { AttackPathGraphData, GraphEdge, GraphNode } from "@/types/attack-paths";

import { NODE_CATEGORY, resolveNodeVisual } from "./node-visuals";

// Marker labels for synthetic nodes. The graph pipeline (layout, node
// components, click handling) keys off these.
export const ATTACK_PATH_GROUP_LABEL = "AttackPathGroup";
export const ATTACK_PATH_OUTCOME_LABEL = "AttackPathOutcome";

export const OUTCOME_NODE_ID = "attack-path-outcome";

// Synthetic edge types — chosen so they never collide with real Cartography
// relationship types (and so layout's container-reversal never touches them).
const TEMPLATE_EDGE_TYPE = "ATTACK_STEP";
const OUTCOME_EDGE_TYPE = "LEADS_TO";

export interface AttackPathOutcome {
  label: string;
  description: string;
  severity: string;
}

const isFindingNode = (node: GraphNode): boolean =>
  node.labels.some((label) => label.toLowerCase().includes("finding"));

export const isGroupNode = (node: GraphNode): boolean =>
  node.labels.includes(ATTACK_PATH_GROUP_LABEL);

export const isOutcomeNode = (node: GraphNode): boolean =>
  node.labels.includes(ATTACK_PATH_OUTCOME_LABEL);

/** Stable grouping key for a node: its human resource type (e.g. "AWS Role"). */
export const nodeTypeKey = (node: GraphNode): string =>
  resolveNodeVisual(node).description;

const groupNodeId = (typeKey: string): string => `group:${typeKey}`;

const makeGroupNode = (typeKey: string, members: GraphNode[]): GraphNode => ({
  // Carry the representative member's labels (after the marker) so node-visuals
  // resolves the correct icon/colors for the type.
  id: groupNodeId(typeKey),
  labels: [ATTACK_PATH_GROUP_LABEL, ...members[0].labels],
  properties: {
    typeKey,
    count: members.length,
  },
});

const makeOutcomeNode = (outcome: AttackPathOutcome): GraphNode => ({
  id: OUTCOME_NODE_ID,
  labels: [ATTACK_PATH_OUTCOME_LABEL],
  properties: {
    label: outcome.label,
    description: outcome.description,
    severity: outcome.severity,
  },
});

/**
 * Build the grouped template graph from the concrete attack-path graph.
 *
 * @param data          Concrete graph (nodes + edges) from the API/adapter.
 * @param expandedTypes Set of type keys currently expanded into members.
 * @param outcome       Attack outcome metadata (terminal node), or null.
 */
export const buildTemplateGraph = (
  data: AttackPathGraphData | null,
  expandedTypes: ReadonlySet<string>,
  outcome: AttackPathOutcome | null,
): AttackPathGraphData => {
  const nodes = data?.nodes ?? [];
  const edges = data?.edges ?? [];

  const nodeById = new Map(nodes.map((node) => [node.id, node]));

  // Keep resource + internet nodes; drop findings and (defensively) accounts.
  const relevant = nodes.filter((node) => {
    if (isFindingNode(node)) return false;
    return resolveNodeVisual(node).category !== NODE_CATEGORY.ACCOUNT;
  });
  const relevantIds = new Set(relevant.map((node) => node.id));

  const isInternet = (node: GraphNode): boolean =>
    resolveNodeVisual(node).category === NODE_CATEGORY.INTERNET;

  // Group resource nodes by type. Internet nodes stay concrete (single entry).
  const membersByType = new Map<string, GraphNode[]>();
  relevant.forEach((node) => {
    if (isInternet(node)) return;
    const key = nodeTypeKey(node);
    const list = membersByType.get(key) ?? [];
    list.push(node);
    membersByType.set(key, list);
  });

  // Map a concrete node id to the id of the node that represents it in the
  // template: itself when its type is expanded (or internet), else its group.
  const repOf = (id: string): string | null => {
    const node = nodeById.get(id);
    if (!node || !relevantIds.has(id)) return null;
    if (isInternet(node)) return id;
    const key = nodeTypeKey(node);
    return expandedTypes.has(key) ? id : groupNodeId(key);
  };

  const outNodes: GraphNode[] = [];
  relevant.filter(isInternet).forEach((node) => outNodes.push(node));
  membersByType.forEach((members, key) => {
    if (expandedTypes.has(key)) {
      members.forEach((member) => outNodes.push(member));
    } else {
      outNodes.push(makeGroupNode(key, members));
    }
  });

  // Collapse concrete edges onto representative edges, de-duplicated and with
  // self-loops (intra-group edges) removed.
  const seen = new Set<string>();
  const outEdges: GraphEdge[] = [];
  edges.forEach((edge) => {
    const source = repOf(edge.source);
    const target = repOf(edge.target);
    if (!source || !target || source === target) return;
    const key = `${source}->${target}`;
    if (seen.has(key)) return;
    seen.add(key);
    outEdges.push({
      id: `tmpl:${key}`,
      source,
      target,
      type: TEMPLATE_EDGE_TYPE,
    });
  });

  // Append the outcome node and connect every sink (no outgoing edge) to it.
  if (outcome && outNodes.length > 0) {
    const hasOutgoing = new Set(outEdges.map((edge) => edge.source));
    outNodes
      .filter((node) => !hasOutgoing.has(node.id))
      .forEach((node) => {
        outEdges.push({
          id: `tmpl:outcome:${node.id}`,
          source: node.id,
          target: OUTCOME_NODE_ID,
          type: OUTCOME_EDGE_TYPE,
        });
      });
    outNodes.push(makeOutcomeNode(outcome));
  }

  return { nodes: outNodes, edges: outEdges };
};
