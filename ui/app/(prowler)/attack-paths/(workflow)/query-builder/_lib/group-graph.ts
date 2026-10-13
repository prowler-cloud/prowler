/**
 * Attack-path view transform (pure).
 *
 * Reshapes the raw query graph into the attack-path view before layout:
 *   1. drop the account/provider hub node(s)
 *   2. group each hop by resource class into a single collapsible node
 *      (collapsed by default; expanding shows the individual members)
 *   3. inject a terminal outcome node from the query's outcome metadata
 *
 * Finding nodes are deliberately KEPT: they pass through for members whose class
 * is expanded, and the canvas hides/reveals them per the existing per-resource
 * behaviour (expandedResources). Findings of a collapsed class are omitted, so a
 * collapsed group never drags its members' findings onto the canvas.
 *
 * Ranking and outcome-sink detection use the same edge orientation as the Dagre
 * layout (see edge-orientation), so the injected outcome node stays terminal
 * even when the path runs through reversed container relationships.
 *
 * Kept pure and separate from the store so expand/collapse is a view recompute
 * over stable raw data, never a data mutation.
 */

import type {
  AttackPathGraphData,
  AttackPathOutcome,
  GraphEdge,
  GraphNode,
  GraphRelationship,
} from "@/types/attack-paths";

import { orientEdgeForLayout } from "./edge-orientation";
import { isProwlerFindingNode } from "./node-types";
import { NODE_CATEGORY, resolveNodeVisual } from "./node-visuals";

// Synthetic labels so layout/getNodeType and the node registry can identify the
// injected nodes. Real graph labels never collide with these.
export const GROUP_NODE_LABEL = "__AttackPathGroup";
export const OUTCOME_NODE_LABEL = "__AttackPathOutcome";

// Property keys carried on the synthetic nodes (read by their components).
export const GROUP_PROPS = {
  CLASS: "__groupClass",
  CLASS_NAME: "__groupClassName",
  COUNT: "__groupCount",
  KEY: "__groupKey",
  HAS_FINDINGS: "__groupHasFindings",
  // Set on an expanded member so a double-click can collapse its owning class.
  MEMBER_KEY: "__memberGroupKey",
} as const;

export const OUTCOME_PROPS = {
  KIND: "__outcomeKind",
  LABEL: "__outcomeLabel",
  PARTIAL: "__outcomePartial",
} as const;

const HAS_FINDING = "HAS_FINDING";

interface AttackPathViewInput {
  data: AttackPathGraphData;
  /** Group keys (see groupKey()) that are currently expanded to their members. */
  expandedClasses: ReadonlySet<string>;
  /** From the selected query's metadata; absent for custom queries. */
  outcome?: AttackPathOutcome | null;
}

export interface AttackPathView {
  nodes: GraphNode[];
  edges: GraphEdge[];
  /**
   * groupKey -> ids of the member nodes it represents. Consumed when a class is
   * collapsed so the store can prune expansion/selection state that pointed at a
   * member the collapse just hid.
   */
  groupMembers: Map<string, string[]>;
}

const isAccountHub = (node: GraphNode): boolean =>
  resolveNodeVisual(node).category === NODE_CATEGORY.ACCOUNT;

const isInternet = (node: GraphNode): boolean =>
  resolveNodeVisual(node).category === NODE_CATEGORY.INTERNET;

/** Primary semantic label used as the class key (e.g. "AWSRole"). */
const classLabelOf = (node: GraphNode): string => node.labels[0] ?? "Resource";

/** Deterministic group key: same class at different hops stays distinct. */
export const groupKey = (rank: number, classLabel: string): string =>
  `${rank}::${classLabel}`;

const edgesOf = (data: AttackPathGraphData): GraphEdge[] => {
  if (data.edges && data.edges.length > 0) return data.edges;
  return (data.relationships ?? []).map((r: GraphRelationship) => ({
    id: r.id,
    source: r.source,
    target: r.target,
    type: r.label,
    properties: r.properties,
  }));
};

/**
 * Shortest-hop rank from the fragment sources (in-degree 0). Cycle-safe: ranks
 * only decrease toward the true minimum and are bounded at 0, so it terminates.
 */
const computeRanks = (
  nodes: GraphNode[],
  edges: GraphEdge[],
): Map<string, number> => {
  const adjacency = new Map<string, string[]>();
  const inDegree = new Map<string, number>();
  nodes.forEach((n) => inDegree.set(n.id, 0));
  edges.forEach((e) => {
    adjacency.set(e.source, [...(adjacency.get(e.source) ?? []), e.target]);
    inDegree.set(e.target, (inDegree.get(e.target) ?? 0) + 1);
  });

  const rank = new Map<string, number>();
  const queue: string[] = [];
  nodes.forEach((n) => {
    if ((inDegree.get(n.id) ?? 0) === 0) {
      rank.set(n.id, 0);
      queue.push(n.id);
    }
  });
  // Pure cycle with no source: seed everything at rank 0.
  if (queue.length === 0) {
    nodes.forEach((n) => {
      rank.set(n.id, 0);
      queue.push(n.id);
    });
  }

  while (queue.length > 0) {
    const current = queue.shift() as string;
    const next = (rank.get(current) as number) + 1;
    for (const neighbor of adjacency.get(current) ?? []) {
      if (!rank.has(neighbor) || (rank.get(neighbor) as number) > next) {
        rank.set(neighbor, next);
        queue.push(neighbor);
      }
    }
  }
  nodes.forEach((n) => {
    if (!rank.has(n.id)) rank.set(n.id, 0);
  });
  return rank;
};

const makeGroupNode = (
  key: string,
  classLabel: string,
  className: string,
  total: number,
  hasFindings: boolean,
): GraphNode => ({
  id: `group:${key}`,
  labels: [GROUP_NODE_LABEL],
  properties: {
    [GROUP_PROPS.CLASS]: classLabel,
    [GROUP_PROPS.CLASS_NAME]: className,
    [GROUP_PROPS.COUNT]: total,
    [GROUP_PROPS.KEY]: key,
    [GROUP_PROPS.HAS_FINDINGS]: hasFindings,
  },
});

const makeOutcomeNode = (outcome: AttackPathOutcome): GraphNode => ({
  id: `outcome:${outcome.kind}`,
  labels: [OUTCOME_NODE_LABEL],
  properties: {
    [OUTCOME_PROPS.KIND]: outcome.kind,
    [OUTCOME_PROPS.LABEL]: outcome.label,
    [OUTCOME_PROPS.PARTIAL]: outcome.partial ?? false,
  },
});

export const buildAttackPathView = ({
  data,
  expandedClasses,
  outcome,
}: AttackPathViewInput): AttackPathView => {
  const rawNodes = data?.nodes ?? [];
  const allEdges = edgesOf(data);

  // Partition: findings are kept (see module docs); the account hub is dropped.
  const findingIds = new Set(
    rawNodes.filter((n) => isProwlerFindingNode(n.labels)).map((n) => n.id),
  );
  const resourceNodes = rawNodes.filter(
    (n) => !isAccountHub(n) && !isProwlerFindingNode(n.labels),
  );
  const resourceIds = new Set(resourceNodes.map((n) => n.id));

  // Resource-level edges drive ranking/grouping (findings + hub edges excluded).
  const resourceEdges = allEdges.filter(
    (e) =>
      e.type !== HAS_FINDING &&
      resourceIds.has(e.source) &&
      resourceIds.has(e.target),
  );

  // Rank/sink reasoning must follow the same direction the layout renders, so
  // orient container relationships up front (see edge-orientation).
  const orientedResourceEdges = resourceEdges.map((e) => {
    const [source, target] = orientEdgeForLayout(e.source, e.target, e.type);
    return { ...e, source, target };
  });

  // Which resources carry findings (for the group "has findings" indicator).
  const resourceHasFinding = new Set<string>();
  for (const edge of allEdges) {
    if (edge.type !== HAS_FINDING) continue;
    const findingEnd = findingIds.has(edge.source) ? edge.source : edge.target;
    const resourceEnd = findingEnd === edge.source ? edge.target : edge.source;
    if (findingIds.has(findingEnd) && resourceIds.has(resourceEnd)) {
      resourceHasFinding.add(resourceEnd);
    }
  }

  // Group members by (rank, class).
  const ranks = computeRanks(resourceNodes, orientedResourceEdges);
  const groups = new Map<string, GraphNode[]>();
  for (const node of resourceNodes) {
    const key = groupKey(ranks.get(node.id) ?? 0, classLabelOf(node));
    groups.set(key, [...(groups.get(key) ?? []), node]);
  }

  const groupMembers = new Map<string, string[]>();
  const viewIdOf = new Map<string, string>();
  const outNodes: GraphNode[] = [];

  for (const [key, members] of Array.from(groups.entries())) {
    groupMembers.set(
      key,
      members.map((m) => m.id),
    );
    const isSingleton = members.length === 1;
    const isExpanded = expandedClasses.has(key);

    if (isSingleton || isExpanded) {
      // Expanding a class renders every member — never a subset — so the graph
      // can't present an incomplete attack path as complete.
      for (const member of members) {
        viewIdOf.set(member.id, member.id);
        // Tag expanded members (not lone singletons) so a double-click can
        // collapse the whole class. Clone so raw data stays untouched.
        outNodes.push(
          isSingleton
            ? member
            : {
                ...member,
                properties: {
                  ...member.properties,
                  [GROUP_PROPS.MEMBER_KEY]: key,
                },
              },
        );
      }
    } else {
      const groupId = `group:${key}`;
      const className = resolveNodeVisual(members[0]).description;
      const hasFindings = members.some((m) => resourceHasFinding.has(m.id));
      outNodes.push(
        makeGroupNode(
          key,
          classLabelOf(members[0]),
          className,
          members.length,
          hasFindings,
        ),
      );
      for (const member of members) viewIdOf.set(member.id, groupId);
    }
  }

  // Aggregate resource-level edges between view nodes; dedupe, drop intra-group.
  const edgeMap = new Map<string, GraphEdge>();
  for (const edge of resourceEdges) {
    const source = viewIdOf.get(edge.source);
    const target = viewIdOf.get(edge.target);
    if (!source || !target || source === target) continue;
    const id = `${source}->${target}:${edge.type}`;
    const existing = edgeMap.get(id);
    if (existing) {
      const count = Number(existing.properties?.__count ?? 1) + 1;
      existing.properties = { ...existing.properties, __count: count };
    } else {
      edgeMap.set(id, {
        id,
        source,
        target,
        type: edge.type,
        properties: { ...edge.properties, __count: 1 },
      });
    }
  }
  const resourceViewEdges = Array.from(edgeMap.values());

  // Keep finding nodes + HAS_FINDING edges for members that are visible (i.e.
  // whose class is expanded — a collapsed group hides its members' findings).
  // The canvas then reveals them per the existing per-resource behaviour.
  // Findings not attached to any resource (orphans) pass through as-is, so a
  // findings-only graph still renders, matching current behaviour.
  const findingNodes: GraphNode[] = [];
  const findingEdges: GraphEdge[] = [];
  const includedFindings = new Set<string>();
  const findingsWithResourceEdge = new Set<string>();

  const includeFinding = (findingId: string) => {
    if (includedFindings.has(findingId)) return;
    includedFindings.add(findingId);
    const findingNode = rawNodes.find((n) => n.id === findingId);
    if (findingNode) findingNodes.push(findingNode);
  };

  for (const edge of allEdges) {
    if (edge.type !== HAS_FINDING) continue;
    const findingEnd = findingIds.has(edge.source) ? edge.source : edge.target;
    const resourceEnd = findingEnd === edge.source ? edge.target : edge.source;
    if (!findingIds.has(findingEnd) || !resourceIds.has(resourceEnd)) continue;
    findingsWithResourceEdge.add(findingEnd);
    // Visible only when the resource renders as itself (not collapsed).
    if (viewIdOf.get(resourceEnd) !== resourceEnd) continue;
    findingEdges.push(edge);
    includeFinding(findingEnd);
  }

  // Orphan findings (no HAS_FINDING to any resource) render standalone.
  for (const findingId of Array.from(findingIds)) {
    if (!findingsWithResourceEdge.has(findingId)) includeFinding(findingId);
  }
  outNodes.push(...findingNodes);

  const outEdges = [...resourceViewEdges, ...findingEdges];

  // Inject the outcome node at the resource-level sinks (no outgoing resource
  // edge). Findings/outcome edges do not count toward "has an outgoing edge".
  if (outcome) {
    // A sink has no outgoing edge in the *laid-out* direction, so resolve
    // "outgoing" from the oriented edges — otherwise a reversed container edge
    // makes a terminal node look like it still points onward.
    const hasOutgoing = new Set<string>();
    for (const edge of orientedResourceEdges) {
      const source = viewIdOf.get(edge.source);
      const target = viewIdOf.get(edge.target);
      if (source && target && source !== target) hasOutgoing.add(source);
    }
    const attachable = outNodes.filter(
      (n) =>
        !isInternet(n) &&
        !findingIds.has(n.id) &&
        !n.labels.includes(OUTCOME_NODE_LABEL),
    );
    let sinks = attachable.filter((n) => !hasOutgoing.has(n.id));
    // No sink (SSO-style principal-only, or a cycle): attach to every node.
    if (sinks.length === 0) sinks = attachable;
    if (sinks.length > 0) {
      const outcomeNode = makeOutcomeNode(outcome);
      outNodes.push(outcomeNode);
      for (const sink of sinks) {
        outEdges.push({
          id: `${sink.id}->${outcomeNode.id}:OUTCOME`,
          source: sink.id,
          target: outcomeNode.id,
          type: "OUTCOME",
        });
      }
    }
  }

  return { nodes: outNodes, edges: outEdges, groupMembers };
};
