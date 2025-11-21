"use client";

import type { D3ZoomEvent, ZoomBehavior } from "d3";
import { select, zoom, zoomIdentity } from "d3";
import dagre from "dagre";
import {
  forwardRef,
  type Ref,
  useEffect,
  useImperativeHandle,
  useRef,
  useState,
} from "react";

import type { AttackPathGraphData, GraphNode } from "@/types/attack-paths";

import {
  formatNodeLabel,
  getNodeColor,
  GRAPH_EDGE_COLOR,
  GRAPH_SELECTION_COLOR,
} from "../../_lib";

export interface AttackPathGraphRef {
  zoomIn: () => void;
  zoomOut: () => void;
  resetZoom: () => void;
  getZoomLevel: () => number;
  getSVGElement: () => SVGSVGElement | null;
}

interface AttackPathGraphProps {
  data: AttackPathGraphData;
  onNodeClick?: (node: GraphNode) => void;
  selectedNodeId?: string | null;
  ref?: Ref<AttackPathGraphRef>;
}

/**
 * Node data type used throughout the graph visualization
 */
type NodeData = { id: string; x: number; y: number; data: GraphNode };

/**
 * Node type to icon unicode mapping
 */
const NODE_TYPE_ICONS = {
  prowlerfinding: "⚠",
  awsaccount: "☁",
  ec2instance: "🖥",
  s3bucket: "💾",
  iamrole: "🔑",
  lambdafunction: "λ",
  securitygroup: "🛡",
  default: "●",
} as const;

/**
 * Get icon for node based on label type
 */
function getNodeTypeIcon(labels: string[]): string {
  if (!labels || labels.length === 0) return NODE_TYPE_ICONS.default;

  const label = labels[0].toLowerCase();

  // Try exact matches first
  if (label in NODE_TYPE_ICONS) {
    return NODE_TYPE_ICONS[label as keyof typeof NODE_TYPE_ICONS];
  }

  // Try partial matches
  for (const [key, icon] of Object.entries(NODE_TYPE_ICONS)) {
    if (key !== "default" && label.includes(key)) {
      return icon;
    }
  }

  return NODE_TYPE_ICONS.default;
}

/**
 * D3 + Dagre hierarchical graph visualization for attack paths
 * Renders static hierarchical graph with left-to-right flow
 */
const AttackPathGraphComponent = forwardRef<
  AttackPathGraphRef,
  AttackPathGraphProps
>(({ data, onNodeClick, selectedNodeId }, ref) => {
  const svgRef = useRef<SVGSVGElement>(null);
  const [zoomLevel, setZoomLevel] = useState(1);
  const zoomBehaviorRef = useRef<ZoomBehavior<SVGSVGElement, unknown> | null>(
    null,
  );
  const containerRef = useRef<ReturnType<
    typeof select<SVGGElement, unknown>
  > | null>(null);
  const svgSelectionRef = useRef<ReturnType<
    typeof select<SVGSVGElement, unknown>
  > | null>(null);
  const hiddenNodeIdsRef = useRef<Set<string>>(new Set());
  const onNodeClickRef = useRef(onNodeClick);
  const nodeCirclesRef = useRef<{
    attr(
      name: string,
      value: string | number | ((d: NodeData) => string | number),
    ): {
      attr(
        name: string,
        value: string | number | ((d: NodeData) => string | number),
      ): void;
    };
  } | null>(null);

  // Update ref when onNodeClick changes
  useEffect(() => {
    onNodeClickRef.current = onNodeClick;
  }, [onNodeClick]);

  // Update selected node styling without re-rendering
  useEffect(() => {
    if (nodeCirclesRef.current) {
      nodeCirclesRef.current
        .attr("stroke", (d: NodeData) =>
          d.id === selectedNodeId ? GRAPH_SELECTION_COLOR : "none",
        )
        .attr("stroke-width", (d: NodeData) =>
          d.id === selectedNodeId ? 3 : 0,
        );
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedNodeId]);

  useImperativeHandle(ref, () => ({
    zoomIn: () => {
      if (svgSelectionRef.current && zoomBehaviorRef.current) {
        svgSelectionRef.current
          .transition()
          .duration(300)
          .call(zoomBehaviorRef.current.scaleBy, 1.3);
      }
    },
    zoomOut: () => {
      if (svgSelectionRef.current && zoomBehaviorRef.current) {
        svgSelectionRef.current
          .transition()
          .duration(300)
          .call(zoomBehaviorRef.current.scaleBy, 0.77);
      }
    },
    resetZoom: () => {
      if (
        svgSelectionRef.current &&
        zoomBehaviorRef.current &&
        containerRef.current
      ) {
        const bounds = containerRef.current.node()?.getBBox();
        if (!bounds) return;

        const fullWidth = svgRef.current?.clientWidth || 800;
        const fullHeight = svgRef.current?.clientHeight || 500;

        const midX = bounds.x + bounds.width / 2;
        const midY = bounds.y + bounds.height / 2;
        const scale =
          0.8 / Math.max(bounds.width / fullWidth, bounds.height / fullHeight);
        const tx = fullWidth / 2 - scale * midX;
        const ty = fullHeight / 2 - scale * midY;

        svgSelectionRef.current
          .transition()
          .duration(300)
          .call(
            zoomBehaviorRef.current.transform,
            zoomIdentity.translate(tx, ty).scale(scale),
          );
      }
    },
    getZoomLevel: () => zoomLevel,
    getSVGElement: () => svgRef.current,
  }));

  useEffect(() => {
    if (!svgRef.current || !data.nodes || data.nodes.length === 0) return;

    // Set dimensions based on container size
    const width = svgRef.current.clientWidth || 800;
    const height = svgRef.current.clientHeight || 500;

    // Clear previous content
    select(svgRef.current).selectAll("*").remove();

    // Create SVG
    const svg = select(svgRef.current)
      .attr("width", width)
      .attr("height", height)
      .attr("viewBox", [0, 0, width, height]);

    // Create container for zoom/pan
    const container = svg.append("g") as unknown as ReturnType<
      typeof select<SVGGElement, unknown>
    >;
    containerRef.current = container;
    svgSelectionRef.current = svg as unknown as ReturnType<
      typeof select<SVGSVGElement, unknown>
    >;

    // Container relationships (reverse direction for layout purposes)
    const containerRelations = new Set([
      "RUNS_IN",
      "BELONGS_TO",
      "LOCATED_IN",
      "PART_OF",
    ]);

    // Create dagre graph
    const g = new dagre.graphlib.Graph();
    g.setGraph({
      rankdir: "LR", // Left to right
      nodesep: 80, // Vertical spacing between nodes
      ranksep: 200, // Horizontal spacing between ranks
      marginx: 50,
      marginy: 50,
    });
    g.setDefaultEdgeLabel(() => ({}));

    // Initially hide finding nodes
    const initialHiddenNodes = new Set<string>();
    data.nodes.forEach((node) => {
      const isFinding = node.labels.some((label) =>
        label.toLowerCase().includes("finding"),
      );
      if (isFinding) {
        initialHiddenNodes.add(node.id);
      }
    });
    hiddenNodeIdsRef.current = initialHiddenNodes;

    // Create a map to store original node data
    const nodeDataMap = new Map(data.nodes.map((node) => [node.id, node]));

    // Add nodes to dagre graph
    data.nodes.forEach((node) => {
      g.setNode(node.id, {
        label: node.id,
        width: 90,
        height: 90,
      });
    });

    // Add edges to dagre graph
    if (data.edges && Array.isArray(data.edges)) {
      data.edges.forEach((edge) => {
        const source = edge.source;
        const target = edge.target;
        let sourceId =
          typeof source === "string"
            ? source
            : typeof source === "object" && source !== null
              ? (source as GraphNode).id
              : "";
        let targetId =
          typeof target === "string"
            ? target
            : typeof target === "object" && target !== null
              ? (target as GraphNode).id
              : "";

        // Reverse container relationships for proper hierarchy
        if (containerRelations.has(edge.type)) {
          [sourceId, targetId] = [targetId, sourceId];
        }

        if (sourceId && targetId) {
          g.setEdge(sourceId, targetId, {
            originalSource:
              typeof edge.source === "string"
                ? edge.source
                : (edge.source as GraphNode).id,
            originalTarget:
              typeof edge.target === "string"
                ? edge.target
                : (edge.target as GraphNode).id,
          });
        }
      });
    }

    // Run dagre layout
    dagre.layout(g);

    // Draw edges
    const edgesData: Array<{
      source: { x: number; y: number };
      target: { x: number; y: number };
      id: string;
      sourceId: string;
      targetId: string;
    }> = [];
    g.edges().forEach((e) => {
      const sourceNode = g.node(e.v);
      const targetNode = g.node(e.w);

      edgesData.push({
        source: { x: sourceNode.x, y: sourceNode.y },
        target: { x: targetNode.x, y: targetNode.y },
        id: `${e.v}-${e.w}`,
        sourceId: e.v,
        targetId: e.w,
      });
    });

    const linkGroup = container.append("g").attr("class", "links");

    const linkElements = linkGroup
      .selectAll("line")
      .data(edgesData)
      .enter()
      .append("line")
      .attr("x1", (d) => d.source.x)
      .attr("y1", (d) => d.source.y)
      .attr("x2", (d) => d.target.x)
      .attr("y2", (d) => d.target.y)
      .attr("stroke", GRAPH_EDGE_COLOR)
      .attr("stroke-opacity", 0.6)
      .attr("stroke-width", 2)
      .attr("marker-end", "url(#arrowhead)")
      .style("display", (d) => {
        // Hide edges connected to hidden nodes
        return hiddenNodeIdsRef.current.has(d.sourceId) ||
          hiddenNodeIdsRef.current.has(d.targetId)
          ? "none"
          : null;
      });

    // Add arrow marker definition
    svg
      .append("defs")
      .append("marker")
      .attr("id", "arrowhead")
      .attr("viewBox", "0 0 10 10")
      .attr("refX", 9)
      .attr("refY", 5)
      .attr("markerWidth", 6)
      .attr("markerHeight", 6)
      .attr("orient", "auto")
      .append("path")
      .attr("d", "M 0 0 L 10 5 L 0 10 z")
      .attr("fill", GRAPH_EDGE_COLOR);

    // Draw nodes
    const nodesData = g.nodes().map((v) => {
      const node = g.node(v);
      return {
        id: v,
        x: node.x,
        y: node.y,
        data: nodeDataMap.get(v)!,
      };
    });

    const nodeGroup = container.append("g").attr("class", "nodes");

    const nodeElements = nodeGroup
      .selectAll("g.node")
      .data(nodesData)
      .enter()
      .append("g")
      .attr("class", "node")
      .attr("transform", (d) => `translate(${d.x},${d.y})`)
      .attr("cursor", "pointer")
      .style("display", (d) =>
        hiddenNodeIdsRef.current.has(d.id) ? "none" : null,
      )
      .on("click", function (event: PointerEvent, d) {
        event.stopPropagation();

        // Toggle visibility of connected finding nodes
        const node = d.data;
        const isFinding = node.labels.some((label) =>
          label.toLowerCase().includes("finding"),
        );

        if (!isFinding) {
          // Find connected findings for THIS node
          const connectedFindings = new Set<string>();
          data.edges?.forEach((edge) => {
            const sourceId =
              typeof edge.source === "string"
                ? edge.source
                : (edge.source as GraphNode).id;
            const targetId =
              typeof edge.target === "string"
                ? edge.target
                : (edge.target as GraphNode).id;

            if (sourceId === node.id || targetId === node.id) {
              const otherId = sourceId === node.id ? targetId : sourceId;
              const otherNode = data.nodes.find((n) => n.id === otherId);
              if (
                otherNode?.labels.some((label) =>
                  label.toLowerCase().includes("finding"),
                )
              ) {
                connectedFindings.add(otherId);
              }
            }
          });

          // Clear hidden nodes and hide ALL findings
          hiddenNodeIdsRef.current.clear();
          data.nodes.forEach((n) => {
            const isNodeFinding = n.labels.some((label) =>
              label.toLowerCase().includes("finding"),
            );
            if (isNodeFinding) {
              hiddenNodeIdsRef.current.add(n.id);
            }
          });

          // Show ONLY the findings connected to the clicked node
          connectedFindings.forEach((findingId) => {
            hiddenNodeIdsRef.current.delete(findingId);
          });

          // Update node visibility
          nodeElements.style(
            "display",
            function (nodeData: {
              id: string;
              x: number;
              y: number;
              data: GraphNode;
            }) {
              return hiddenNodeIdsRef.current.has(nodeData.id) ? "none" : null;
            },
          );

          // Update edge visibility
          linkElements.style(
            "display",
            function (edgeData: {
              source: { x: number; y: number };
              target: { x: number; y: number };
              id: string;
              sourceId: string;
              targetId: string;
            }) {
              return hiddenNodeIdsRef.current.has(edgeData.sourceId) ||
                hiddenNodeIdsRef.current.has(edgeData.targetId)
                ? "none"
                : null;
            },
          );

          // Auto-adjust view to show the selected node and its findings
          setTimeout(() => {
            if (
              svgSelectionRef.current &&
              zoomBehaviorRef.current &&
              containerRef.current
            ) {
              // Calculate bounding box of visible nodes (clicked node + its findings)
              const visibleNodeIds = new Set([
                node.id,
                ...Array.from(connectedFindings),
              ]);
              const visibleNodesData = nodesData.filter((n) =>
                visibleNodeIds.has(n.id),
              );

              if (visibleNodesData.length > 0) {
                // Find min/max coordinates of visible nodes
                let minX = Infinity,
                  maxX = -Infinity,
                  minY = Infinity,
                  maxY = -Infinity;
                visibleNodesData.forEach((n) => {
                  minX = Math.min(minX, n.x);
                  maxX = Math.max(maxX, n.x);
                  minY = Math.min(minY, n.y);
                  maxY = Math.max(maxY, n.y);
                });

                // Add padding (node radius + extra space)
                const padding = 100;
                minX -= padding;
                maxX += padding;
                minY -= padding;
                maxY += padding;

                const fullWidth = svgRef.current?.clientWidth || 800;
                const fullHeight = svgRef.current?.clientHeight || 500;

                const width = maxX - minX;
                const height = maxY - minY;
                const midX = minX + width / 2;
                const midY = minY + height / 2;

                // Calculate scale to fit all visible nodes
                const scale =
                  0.9 / Math.max(width / fullWidth, height / fullHeight);
                const tx = fullWidth / 2 - scale * midX;
                const ty = fullHeight / 2 - scale * midY;

                svgSelectionRef.current
                  .transition()
                  .duration(500)
                  .call(
                    zoomBehaviorRef.current.transform,
                    zoomIdentity.translate(tx, ty).scale(scale),
                  );
              }
            }
          }, 50);
        }

        onNodeClickRef.current?.(d.data);
      });

    // Add tooltip
    nodeElements.append("title").text((d: (typeof nodesData)[0]): string => {
      const isFinding = d.data.labels.some((label) =>
        label.toLowerCase().includes("finding"),
      );
      const label =
        d.data.labels && d.data.labels.length > 0
          ? formatNodeLabel(d.data.labels[0])
          : d.id;

      if (isFinding) {
        return `${label}\nClick to view finding details`;
      } else {
        return `${label}\nClick to view related findings`;
      }
    });

    // Add circles
    const nodeCircles = nodeElements
      .append("circle")
      .attr("r", 45)
      .attr("fill", (d) => getNodeColor(d.data.labels))
      .attr("opacity", 0.8)
      .attr("stroke", (d) =>
        d.id === selectedNodeId ? GRAPH_SELECTION_COLOR : "none",
      )
      .attr("stroke-width", (d) => (d.id === selectedNodeId ? 3 : 0));

    // Store reference for updating selection later
    nodeCirclesRef.current = nodeCircles;

    // Add label text
    const textGroups = nodeElements
      .append("text")
      .attr("pointer-events", "none");

    // Icon
    textGroups
      .append("tspan")
      .attr("x", 0)
      .attr("dy", "-0.4em")
      .attr("font-size", "16px")
      .attr("fill", "white")
      .attr("opacity", 0.9)
      .attr("text-anchor", "middle")
      .text((d) => getNodeTypeIcon(d.data.labels));

    // Type
    textGroups
      .append("tspan")
      .attr("x", 0)
      .attr("dy", "1.3em")
      .attr("font-size", "10px")
      .attr("fill", "white")
      .attr("font-weight", "bold")
      .attr("text-anchor", "middle")
      .text((d) => {
        const type =
          d.data.labels && d.data.labels.length > 0
            ? formatNodeLabel(d.data.labels[0])
            : "Unknown";
        return type.length > 16 ? type.substring(0, 16) + "." : type;
      });

    // ID or severity
    textGroups
      .append("tspan")
      .attr("x", 0)
      .attr("dy", "1.2em")
      .attr("font-size", "9px")
      .attr("fill", "white")
      .attr("text-anchor", "middle")
      .text((d) => {
        const severity = d.data.properties?.severity;
        return severity ? String(severity) : d.id.substring(0, 8);
      });

    // Add zoom behavior (but disable all mouse interactions)
    const zoomBehavior = zoom<SVGSVGElement, unknown>().on(
      "zoom",
      (event: D3ZoomEvent<SVGSVGElement, unknown>) => {
        const transform = event.transform;
        container.attr("transform", transform.toString());
        setZoomLevel(transform.k);
      },
    );
    zoomBehaviorRef.current = zoomBehavior;

    svg.call(zoomBehavior);

    // Disable ALL mouse zoom/pan interactions (only allow programmatic zoom via buttons)
    svg.on("wheel.zoom", null);
    svg.on("dblclick.zoom", null);

    // Auto-fit to screen
    setTimeout(() => {
      if (
        svgSelectionRef.current &&
        zoomBehaviorRef.current &&
        containerRef.current
      ) {
        const bounds = containerRef.current.node()?.getBBox();
        if (!bounds) return;

        const fullWidth = svgRef.current?.clientWidth || 800;
        const fullHeight = svgRef.current?.clientHeight || 500;

        const midX = bounds.x + bounds.width / 2;
        const midY = bounds.y + bounds.height / 2;
        const scale =
          0.8 / Math.max(bounds.width / fullWidth, bounds.height / fullHeight);
        const tx = fullWidth / 2 - scale * midX;
        const ty = fullHeight / 2 - scale * midY;

        svgSelectionRef.current.call(
          zoomBehaviorRef.current.transform,
          zoomIdentity.translate(tx, ty).scale(scale),
        );
      }
    }, 100);
  }, [data]);

  return (
    <svg
      ref={svgRef}
      className="dark:bg-bg-neutral-secondary bg-bg-neutral-secondary h-full w-full rounded-lg"
    />
  );
});

AttackPathGraphComponent.displayName = "AttackPathGraph";

export const AttackPathGraph = AttackPathGraphComponent;
