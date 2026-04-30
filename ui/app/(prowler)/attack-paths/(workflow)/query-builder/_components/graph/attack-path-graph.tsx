"use client";

import "@xyflow/react/dist/style.css";

import {
  Background,
  MiniMap,
  type Node,
  ReactFlow,
  ReactFlowProvider,
  type Rect,
  useReactFlow,
} from "@xyflow/react";
import { useTheme } from "next-themes";
import {
  type MouseEvent,
  type Ref,
  useEffect,
  useImperativeHandle,
  useLayoutEffect,
  useRef,
  useState,
} from "react";

import { cn } from "@/lib/utils";
import type { AttackPathGraphData, GraphNode } from "@/types/attack-paths";

import {
  getNodeBorderColor,
  getNodeColor,
  getPathEdges,
  GRAPH_EDGE_HIGHLIGHT_COLOR,
} from "../../_lib";
import { computeFilteredSubgraph } from "../../_lib/graph-utils";
import { isFindingNode, layoutWithDagre } from "../../_lib/layout";
import { FindingNode } from "./nodes/finding-node";
import { InternetNode } from "./nodes/internet-node";
import { ResourceNode } from "./nodes/resource-node";

// --- Types ---

export interface GraphHandle {
  zoomIn: () => void;
  zoomOut: () => void;
  resetZoom: () => void;
  getZoomLevel: () => number;
  getContainerElement: () => HTMLDivElement | null;
  getNodesBounds: () => Rect | null;
}

interface AttackPathGraphProps {
  data: AttackPathGraphData;
  selectedNodeId?: string | null;
  isFilteredView?: boolean;
  initialNodeId?: string;
  onNodeClick?: (node: GraphNode) => void;
  onInitialFilter?: (filteredData: AttackPathGraphData) => void;
  ref?: Ref<GraphHandle>;
  className?: string;
}

// --- Node type registry (stable reference) ---

const NODE_TYPES = {
  finding: FindingNode,
  internet: InternetNode,
  resource: ResourceNode,
} as const;

// --- CSS for animated dashed edges, selected node pulse, and edge highlight ---

const GRAPH_STYLES = `
  @keyframes dash {
    to { stroke-dashoffset: -20; }
  }
  .react-flow .finding-edge .react-flow__edge-path {
    stroke-dasharray: 8 6;
    animation: dash 1s linear infinite;
  }
  @keyframes selectedPulse {
    0%, 100% { stroke-opacity: 1; }
    50% { stroke-opacity: 0.6; }
  }
  .selected-node {
    animation: selectedPulse 1.2s ease-in-out infinite;
  }
  .react-flow .highlighted .react-flow__edge-path {
    stroke: ${GRAPH_EDGE_HIGHLIGHT_COLOR};
    stroke-width: 3;
    filter: drop-shadow(0 0 4px ${GRAPH_EDGE_HIGHLIGHT_COLOR});
  }
`;

// --- SVG filter color constants ---

const GRAPH_FINDING_GLOW_COLOR = "#ef4444";
const GRAPH_SELECTED_GLOW_COLOR = "#f97316";

// --- SVG filter defs (shared by all node components) ---

const GraphDefs = () => (
  <svg width={0} height={0} className="absolute" aria-hidden="true">
    <defs>
      {/* Glow filter for finding nodes */}
      <filter id="glow">
        <feGaussianBlur stdDeviation="3" result="coloredBlur" />
        <feMerge>
          <feMergeNode in="coloredBlur" />
          <feMergeNode in="SourceGraphic" />
        </feMerge>
      </filter>
      {/* Red glow for resources with findings */}
      <filter id="redGlow">
        <feDropShadow
          dx="0"
          dy="0"
          stdDeviation="4"
          floodColor={GRAPH_FINDING_GLOW_COLOR}
          floodOpacity="0.6"
        />
      </filter>
      {/* Orange glow for selected nodes */}
      <filter id="selectedGlow">
        <feDropShadow
          dx="0"
          dy="0"
          stdDeviation="6"
          floodColor={GRAPH_SELECTED_GLOW_COLOR}
          floodOpacity="0.8"
        />
      </filter>
    </defs>
  </svg>
);

// --- Inner component: calls useReactFlow(), owns layout derivation ---

type GraphCanvasProps = Omit<AttackPathGraphProps, "className">;

const MINIMAP_COLORS = {
  light: {
    bg: "#f8fafc",
    mask: "rgba(241, 245, 249, 0.6)",
    maskStroke: "#cbd5e1",
  },
  dark: {
    bg: "#0f172a",
    mask: "rgba(15, 23, 42, 0.6)",
    maskStroke: "#475569",
  },
} as const;

const GraphCanvas = ({
  data,
  selectedNodeId,
  isFilteredView,
  initialNodeId,
  onNodeClick,
  onInitialFilter,
  ref,
}: GraphCanvasProps) => {
  const { zoomIn, zoomOut, fitView, getZoom, getNodes, getNodesBounds } =
    useReactFlow();
  const { resolvedTheme } = useTheme();
  const containerRef = useRef<HTMLDivElement>(null);
  const hasInitialized = useRef(false);

  const minimapColors =
    resolvedTheme === "dark" ? MINIMAP_COLORS.dark : MINIMAP_COLORS.light;

  // Tier 1 state: which resource nodes have their findings expanded
  const [expandedResources, setExpandedResources] = useState<Set<string>>(
    new Set(),
  );
  // Path highlight state
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);

  // Reset interaction state whenever the underlying graph data changes
  // (e.g. scan switch or new query execution) to avoid leaking stale
  // expansion / highlight state into the next graph.
  useEffect(() => {
    setExpandedResources(new Set());
    setHoveredNodeId(null);
  }, [data]);

  // --- initialNodeId: synchronous filtered-view derivation on first render ---
  // Compute the effective data: if initialNodeId is set and valid, derive filtered subgraph
  let effectiveData = data;
  if (
    initialNodeId &&
    !hasInitialized.current &&
    data.nodes.some((n) => n.id === initialNodeId)
  ) {
    effectiveData = computeFilteredSubgraph(data, initialNodeId);
  }

  // Sync store flags via useLayoutEffect (runs before paint)
  useLayoutEffect(() => {
    if (hasInitialized.current) return;
    hasInitialized.current = true;
    if (
      initialNodeId &&
      data.nodes.some((n) => n.id === initialNodeId) &&
      onInitialFilter
    ) {
      onInitialFilter(effectiveData);
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps -- one-time init

  const nodes = effectiveData.nodes ?? [];
  const edges = effectiveData.edges ?? [];

  // Derive RF nodes and edges from data (pure computation in render body — D4)
  const { rfNodes, rfEdges } = layoutWithDagre(nodes, edges);

  // Pre-compute which resources have findings connected (O(n+e))
  const findingNodeIds = new Set<string>();
  const resourceToFindings = new Map<string, Set<string>>();
  const findingToResources = new Map<string, Set<string>>();

  nodes.forEach((n) => {
    if (isFindingNode(n.labels)) findingNodeIds.add(n.id);
  });

  const resourcesWithFindings = new Set<string>();
  edges.forEach((edge) => {
    const sourceIsFinding = findingNodeIds.has(edge.source);
    const targetIsFinding = findingNodeIds.has(edge.target);

    if (sourceIsFinding) {
      resourcesWithFindings.add(edge.target);
      // Map resource → its findings
      const findings = resourceToFindings.get(edge.target) ?? new Set();
      findings.add(edge.source);
      resourceToFindings.set(edge.target, findings);
      // Map finding → its resources
      const resources = findingToResources.get(edge.source) ?? new Set();
      resources.add(edge.target);
      findingToResources.set(edge.source, resources);
    }
    if (targetIsFinding) {
      resourcesWithFindings.add(edge.source);
      const findings = resourceToFindings.get(edge.source) ?? new Set();
      findings.add(edge.target);
      resourceToFindings.set(edge.source, findings);
      const resources = findingToResources.get(edge.target) ?? new Set();
      resources.add(edge.source);
      findingToResources.set(edge.target, resources);
    }
  });

  // Tier 1: compute which finding nodes are hidden (not expanded)
  const hiddenFindingIds = new Set<string>();
  if (!isFilteredView) {
    findingNodeIds.forEach((findingId) => {
      // A finding is visible only if at least one of its connected resources is expanded
      const connectedResources = findingToResources.get(findingId);
      if (!connectedResources) {
        hiddenFindingIds.add(findingId);
        return;
      }
      const anyExpanded = Array.from(connectedResources).some((resId) =>
        expandedResources.has(resId),
      );
      if (!anyExpanded) {
        hiddenFindingIds.add(findingId);
      }
    });
  }

  // Path highlight: compute highlighted edge IDs
  const highlightedEdgeIds = hoveredNodeId
    ? getPathEdges(
        hoveredNodeId,
        rfEdges.map((e) => ({ sourceId: e.source, targetId: e.target })),
      )
    : new Set<string>();

  // Enrich nodes with selection, hasFindings, and hidden state
  const enrichedNodes = rfNodes.map((node) => ({
    ...node,
    selected: node.id === selectedNodeId,
    hidden: hiddenFindingIds.has(node.id),
    data: {
      ...node.data,
      hasFindings: resourcesWithFindings.has(node.id),
    },
  }));

  // Enrich edges with hidden state (hide edges to hidden findings) and highlight
  const enrichedEdges = rfEdges.map((edge) => {
    const sourceHidden = hiddenFindingIds.has(edge.source);
    const targetHidden = hiddenFindingIds.has(edge.target);
    const isHighlighted = highlightedEdgeIds.has(edge.id);

    return {
      ...edge,
      hidden: sourceHidden || targetHidden,
      className: cn(edge.className, isHighlighted && "highlighted"),
    };
  });

  useImperativeHandle(ref, () => ({
    zoomIn: () => zoomIn({ duration: 300 }),
    zoomOut: () => zoomOut({ duration: 300 }),
    resetZoom: () => fitView({ duration: 300 }),
    getZoomLevel: () => getZoom(),
    getContainerElement: () => containerRef.current,
    getNodesBounds: () => {
      const rfNodes = getNodes();
      if (rfNodes.length === 0) return null;
      return getNodesBounds(rfNodes);
    },
  }));

  const handleNodeClick = (_event: MouseEvent, node: Node) => {
    const graphNode = (node.data as { graphNode: GraphNode }).graphNode;

    // Tier 1: clicking resource in full view toggles connected findings
    if (!isFilteredView && !isFindingNode(graphNode.labels)) {
      if (resourcesWithFindings.has(node.id)) {
        setExpandedResources((prev) => {
          const next = new Set(prev);
          if (next.has(node.id)) {
            next.delete(node.id);
          } else {
            next.add(node.id);
          }
          return next;
        });
      }
    }

    // Always fire parent callback (handles selection + Tier 2 filtered view)
    onNodeClick?.(graphNode);
  };

  // Path highlight on hover
  const handleNodeMouseEnter = (_event: MouseEvent, node: Node) => {
    setHoveredNodeId(node.id);
  };

  const handleNodeMouseLeave = () => {
    setHoveredNodeId(null);
  };

  return (
    <div ref={containerRef} className="h-full w-full">
      <ReactFlow
        nodes={enrichedNodes}
        edges={enrichedEdges}
        nodeTypes={NODE_TYPES}
        onNodeClick={handleNodeClick}
        onNodeMouseEnter={handleNodeMouseEnter}
        onNodeMouseLeave={handleNodeMouseLeave}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        zoomOnScroll={false}
        zoomOnPinch={true}
        zoomOnDoubleClick={false}
        panOnScroll={false}
        minZoom={0.1}
        maxZoom={10}
        proOptions={{ hideAttribution: true }}
      >
        <Background />
        <MiniMap
          pannable
          zoomable
          ariaLabel="Graph minimap"
          bgColor={minimapColors.bg}
          maskColor={minimapColors.mask}
          maskStrokeColor={minimapColors.maskStroke}
          nodeColor={(node) => {
            const graphNode = (node.data as { graphNode?: GraphNode })
              .graphNode;
            if (!graphNode) return MINIMAP_COLORS.light.maskStroke;
            return getNodeColor(graphNode.labels, graphNode.properties);
          }}
          nodeStrokeColor={(node) => {
            const graphNode = (node.data as { graphNode?: GraphNode })
              .graphNode;
            if (!graphNode) return "transparent";
            return getNodeBorderColor(graphNode.labels, graphNode.properties);
          }}
        />
      </ReactFlow>
    </div>
  );
};

// --- Outer component: renders ReactFlowProvider ---

export const AttackPathGraph = ({
  data,
  selectedNodeId,
  isFilteredView,
  initialNodeId,
  onNodeClick,
  onInitialFilter,
  ref,
  className,
}: AttackPathGraphProps) => {
  return (
    <div
      role="img"
      aria-label="Attack path graph"
      className={cn(
        "dark:bg-bg-neutral-secondary bg-bg-neutral-secondary h-full w-full rounded-lg",
        className,
      )}
    >
      <style>{GRAPH_STYLES}</style>
      <GraphDefs />
      <ReactFlowProvider>
        <GraphCanvas
          ref={ref}
          data={data}
          selectedNodeId={selectedNodeId}
          isFilteredView={isFilteredView}
          initialNodeId={initialNodeId}
          onNodeClick={onNodeClick}
          onInitialFilter={onInitialFilter}
        />
      </ReactFlowProvider>
    </div>
  );
};
