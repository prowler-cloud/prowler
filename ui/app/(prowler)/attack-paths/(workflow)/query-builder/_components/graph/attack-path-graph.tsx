"use client";

import "@xyflow/react/dist/style.css";

import {
  Background,
  type Node,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
} from "@xyflow/react";
import { type Ref, useImperativeHandle, useRef } from "react";

import { cn } from "@/lib/utils";
import type { AttackPathGraphData, GraphNode } from "@/types/attack-paths";

import { layoutWithDagre } from "../../_lib/layout";
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
}

interface AttackPathGraphProps {
  data: AttackPathGraphData;
  selectedNodeId?: string | null;
  initialNodeId?: string;
  onNodeClick?: (node: GraphNode) => void;
  ref?: Ref<GraphHandle>;
  className?: string;
}

// --- Node type registry (stable reference) ---

const NODE_TYPES = {
  finding: FindingNode,
  internet: InternetNode,
  resource: ResourceNode,
} as const;

// --- CSS for animated dashed edges and selected node pulse ---

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
`;

// --- SVG filter defs (shared by all node components) ---

const GraphDefs = () => (
  <svg width={0} height={0} className="absolute">
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
          floodColor="#ef4444"
          floodOpacity="0.6"
        />
      </filter>
      {/* Orange glow for selected nodes */}
      <filter id="selectedGlow">
        <feDropShadow
          dx="0"
          dy="0"
          stdDeviation="6"
          floodColor="#f97316"
          floodOpacity="0.8"
        />
      </filter>
    </defs>
  </svg>
);

// --- Inner component: calls useReactFlow(), owns layout derivation ---

interface GraphCanvasProps {
  data: AttackPathGraphData;
  selectedNodeId?: string | null;
  onNodeClick?: (node: GraphNode) => void;
  ref?: Ref<GraphHandle>;
}

const GraphCanvas = ({
  data,
  selectedNodeId,
  onNodeClick,
  ref,
}: GraphCanvasProps) => {
  const { zoomIn, zoomOut, fitView, getZoom } = useReactFlow();
  const containerRef = useRef<HTMLDivElement>(null);

  const nodes = data.nodes ?? [];
  const edges = data.edges ?? [];

  // Derive RF nodes and edges from data (pure computation in render body — D4)
  const { rfNodes, rfEdges } = layoutWithDagre(nodes, edges);

  // Enrich nodes with selection and hasFindings state
  const enrichedNodes = rfNodes.map((node) => ({
    ...node,
    selected: node.id === selectedNodeId,
    data: {
      ...node.data,
      hasFindings: edges.some((edge) => {
        const isConnected = edge.source === node.id || edge.target === node.id;
        if (!isConnected) return false;
        const otherId = edge.source === node.id ? edge.target : edge.source;
        const otherNode = nodes.find((n) => n.id === otherId);
        return otherNode?.labels.some((l) =>
          l.toLowerCase().includes("finding"),
        );
      }),
    },
  }));

  useImperativeHandle(ref, () => ({
    zoomIn: () => zoomIn({ duration: 300 }),
    zoomOut: () => zoomOut({ duration: 300 }),
    resetZoom: () => fitView({ duration: 300 }),
    getZoomLevel: () => getZoom(),
    getContainerElement: () => containerRef.current,
  }));

  const handleNodeClick = (_event: React.MouseEvent, node: Node) => {
    const graphNode = (node.data as { graphNode: GraphNode }).graphNode;
    onNodeClick?.(graphNode);
  };

  // Ctrl+scroll zoom handler: only zoom when Ctrl/Cmd is pressed
  const handleWheel = (event: React.WheelEvent) => {
    if (!event.ctrlKey && !event.metaKey) {
      // Allow normal page scroll — do nothing, React Flow's zoomOnScroll is off
      return;
    }
    // ctrlKey+scroll is handled natively by React Flow's zoomOnPinch
  };

  return (
    <div ref={containerRef} className="h-full w-full">
      <ReactFlow
        nodes={enrichedNodes}
        edges={rfEdges}
        nodeTypes={NODE_TYPES}
        onNodeClick={handleNodeClick}
        onWheel={handleWheel}
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
      </ReactFlow>
    </div>
  );
};

// --- Outer component: renders ReactFlowProvider ---

export const AttackPathGraph = ({
  data,
  selectedNodeId,
  onNodeClick,
  ref,
  className,
}: AttackPathGraphProps) => {
  return (
    <div
      className={cn(
        "dark:bg-bg-neutral-secondary bg-bg-neutral-secondary h-full w-full rounded-lg",
        className,
      )}
    >
      <style dangerouslySetInnerHTML={{ __html: GRAPH_STYLES }} />
      <GraphDefs />
      <ReactFlowProvider>
        <GraphCanvas
          ref={ref}
          data={data}
          selectedNodeId={selectedNodeId}
          onNodeClick={onNodeClick}
        />
      </ReactFlowProvider>
    </div>
  );
};
