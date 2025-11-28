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
  getNodeBorderColor,
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

// Node dimensions - modern rounded pill style
const NODE_WIDTH = 180;
const NODE_HEIGHT = 50;
const NODE_RADIUS = 25; // Fully rounded ends for pill shape
const HEXAGON_WIDTH = 200; // Width for finding hexagons
const HEXAGON_HEIGHT = 55; // Height for finding hexagons

/**
 * D3 + Dagre hierarchical graph visualization for attack paths
 * Renders rounded rectangle nodes with dashed edges
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
  const nodeShapesRef = useRef<ReturnType<
    typeof select<SVGRectElement, NodeData>
  > | null>(null);
  const resourcesWithFindingsRef = useRef<Set<string>>(new Set());

  // Update ref when onNodeClick changes
  useEffect(() => {
    onNodeClickRef.current = onNodeClick;
  }, [onNodeClick]);

  // Update selected node styling without re-rendering
  useEffect(() => {
    if (nodeShapesRef.current) {
      const ALERT_BORDER_COLOR = "#ef4444"; // Red 500
      nodeShapesRef.current
        .attr("stroke", (d: NodeData) => {
          const isFinding = d.data.labels.some((label) =>
            label.toLowerCase().includes("finding"),
          );
          const hasFindings = resourcesWithFindingsRef.current.has(d.id);

          // Resources with findings always keep red border
          if (!isFinding && hasFindings) {
            return ALERT_BORDER_COLOR;
          }
          // Selected nodes get selection color
          if (d.id === selectedNodeId) {
            return GRAPH_SELECTION_COLOR;
          }
          // Default border color
          return getNodeBorderColor(d.data.labels, d.data.properties);
        })
        .attr("stroke-width", (d: NodeData) => {
          const isFinding = d.data.labels.some((label) =>
            label.toLowerCase().includes("finding"),
          );
          const hasFindings = resourcesWithFindingsRef.current.has(d.id);

          // Resources with findings keep their wider stroke
          if (!isFinding && hasFindings) {
            return 2.5;
          }
          return d.id === selectedNodeId ? 3 : isFinding ? 2 : 1.5;
        });
    }
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
      ranksep: 150, // Horizontal spacing between ranks
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

    // Add nodes to dagre graph with appropriate sizes
    data.nodes.forEach((node) => {
      const isFinding = node.labels.some((label) =>
        label.toLowerCase().includes("finding"),
      );
      g.setNode(node.id, {
        label: node.id,
        width: isFinding ? HEXAGON_WIDTH : NODE_WIDTH,
        height: isFinding ? HEXAGON_HEIGHT : NODE_HEIGHT,
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

    // Add defs for filters and markers FIRST (before using them)
    const defs = svg.append("defs");

    // Glow filter for nodes
    const glowFilter = defs.append("filter").attr("id", "glow");
    glowFilter
      .append("feGaussianBlur")
      .attr("stdDeviation", "3")
      .attr("result", "coloredBlur");
    const feMerge = glowFilter.append("feMerge");
    feMerge.append("feMergeNode").attr("in", "coloredBlur");
    feMerge.append("feMergeNode").attr("in", "SourceGraphic");

    // Edge glow filter
    const edgeGlowFilter = defs.append("filter").attr("id", "edgeGlow");
    edgeGlowFilter
      .append("feGaussianBlur")
      .attr("stdDeviation", "2")
      .attr("result", "coloredBlur");
    const edgeFeMerge = edgeGlowFilter.append("feMerge");
    edgeFeMerge.append("feMergeNode").attr("in", "coloredBlur");
    edgeFeMerge.append("feMergeNode").attr("in", "SourceGraphic");

    // Red glow filter for resources with findings
    const redGlowFilter = defs.append("filter").attr("id", "redGlow");
    redGlowFilter
      .append("feDropShadow")
      .attr("dx", "0")
      .attr("dy", "0")
      .attr("stdDeviation", "4")
      .attr("flood-color", "#ef4444")
      .attr("flood-opacity", "0.6");

    // Arrow marker - refX=10 places the arrow tip exactly at the line endpoint
    defs
      .append("marker")
      .attr("id", "arrowhead")
      .attr("viewBox", "0 0 10 10")
      .attr("refX", 10)
      .attr("refY", 5)
      .attr("markerWidth", 6)
      .attr("markerHeight", 6)
      .attr("orient", "auto")
      .append("path")
      .attr("d", "M 0 0 L 10 5 L 0 10 z")
      .attr("fill", GRAPH_EDGE_COLOR);

    // Add CSS animation for dashed lines and resource edge styles
    svg.append("style").text(`
      @keyframes dash {
        to {
          stroke-dashoffset: -20;
        }
      }
      .animated-edge {
        animation: dash 1s linear infinite;
      }
      .resource-edge {
        stroke-opacity: 1;
      }
    `);

    const linkGroup = container.append("g").attr("class", "links");

    // Calculate edge endpoints based on node shape
    const getEdgePoints = (
      sourceId: string,
      targetId: string,
      source: { x: number; y: number },
      target: { x: number; y: number },
    ) => {
      const sourceNode = nodeDataMap.get(sourceId);
      const targetNode = nodeDataMap.get(targetId);

      const sourceIsFinding = sourceNode?.labels.some((label) =>
        label.toLowerCase().includes("finding"),
      );
      const targetIsFinding = targetNode?.labels.some((label) =>
        label.toLowerCase().includes("finding"),
      );
      const sourceIsInternet = sourceNode?.labels.some(
        (label) => label.toLowerCase() === "internet",
      );
      const targetIsInternet = targetNode?.labels.some(
        (label) => label.toLowerCase() === "internet",
      );

      // Get appropriate widths based on node type
      // Internet nodes are circles with radius = NODE_HEIGHT * 0.8
      const sourceHalfWidth = sourceIsInternet
        ? NODE_HEIGHT * 0.8
        : sourceIsFinding
          ? HEXAGON_WIDTH / 2
          : NODE_WIDTH / 2;
      const targetHalfWidth = targetIsInternet
        ? NODE_HEIGHT * 0.8
        : targetIsFinding
          ? HEXAGON_WIDTH / 2
          : NODE_WIDTH / 2;

      // Source exits from right side
      const x1 = source.x + sourceHalfWidth;
      const y1 = source.y;

      // Target enters from left side - line ends at node edge, arrow extends from there
      const x2 = target.x - targetHalfWidth;
      const y2 = target.y;

      return { x1, y1, x2, y2 };
    };

    // Helper to check if a node is a finding
    const isNodeFinding = (nodeId: string) => {
      const node = nodeDataMap.get(nodeId);
      return node?.labels.some((label) =>
        label.toLowerCase().includes("finding"),
      );
    };

    const linkElements = linkGroup
      .selectAll("line")
      .data(edgesData)
      .enter()
      .append("line")
      .attr(
        "x1",
        (d) => getEdgePoints(d.sourceId, d.targetId, d.source, d.target).x1,
      )
      .attr(
        "y1",
        (d) => getEdgePoints(d.sourceId, d.targetId, d.source, d.target).y1,
      )
      .attr(
        "x2",
        (d) => getEdgePoints(d.sourceId, d.targetId, d.source, d.target).x2,
      )
      .attr(
        "y2",
        (d) => getEdgePoints(d.sourceId, d.targetId, d.source, d.target).y2,
      )
      .attr("stroke", GRAPH_EDGE_COLOR)
      .attr("stroke-width", 3)
      .attr("stroke-linecap", "round")
      .attr("stroke-dasharray", (d) => {
        // Dashed lines only for edges connected to findings
        const hasFinding =
          isNodeFinding(d.sourceId) || isNodeFinding(d.targetId);
        return hasFinding ? "8,6" : null;
      })
      .attr("class", (d) => {
        // Animate dashed lines
        const hasFinding =
          isNodeFinding(d.sourceId) || isNodeFinding(d.targetId);
        return hasFinding ? "animated-edge" : "resource-edge";
      })
      .attr("marker-end", "url(#arrowhead)")
      .each(function (d) {
        // Resource-to-resource edges are ALWAYS visible
        // Finding edges are only visible when the finding node is visible
        const sourceIsFinding = isNodeFinding(d.sourceId);
        const targetIsFinding = isNodeFinding(d.targetId);

        let visibility = "visible";
        if (sourceIsFinding || targetIsFinding) {
          const sourceHidden = hiddenNodeIdsRef.current.has(d.sourceId);
          const targetHidden = hiddenNodeIdsRef.current.has(d.targetId);
          visibility = sourceHidden || targetHidden ? "hidden" : "visible";
        }

        select(this).style("visibility", visibility);
      });

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
            "visibility",
            function (edgeData: {
              source: { x: number; y: number };
              target: { x: number; y: number };
              id: string;
              sourceId: string;
              targetId: string;
            }) {
              // Resource-to-resource edges are ALWAYS visible
              const sourceIsFinding = isNodeFinding(edgeData.sourceId);
              const targetIsFinding = isNodeFinding(edgeData.targetId);

              if (!sourceIsFinding && !targetIsFinding) {
                return "visible";
              }

              // Finding edges only visible when finding is not hidden
              return hiddenNodeIdsRef.current.has(edgeData.sourceId) ||
                hiddenNodeIdsRef.current.has(edgeData.targetId)
                ? "hidden"
                : "visible";
            },
          );

          // Auto-adjust view to show the selected node and its findings
          setTimeout(() => {
            if (
              svgSelectionRef.current &&
              zoomBehaviorRef.current &&
              containerRef.current &&
              svgRef.current
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
                  minX = Math.min(minX, n.x - NODE_WIDTH / 2);
                  maxX = Math.max(maxX, n.x + NODE_WIDTH / 2);
                  minY = Math.min(minY, n.y - NODE_HEIGHT / 2);
                  maxY = Math.max(maxY, n.y + NODE_HEIGHT / 2);
                });

                // Add padding
                const padding = 80;
                minX -= padding;
                maxX += padding;
                minY -= padding;
                maxY += padding;

                // Get actual SVG dimensions from the DOM
                const svgRect = svgRef.current.getBoundingClientRect();
                const fullWidth = svgRect.width;
                const fullHeight = svgRect.height;

                const boxWidth = maxX - minX;
                const boxHeight = maxY - minY;
                const midX = minX + boxWidth / 2;
                const midY = minY + boxHeight / 2;

                // Calculate scale to fit all visible nodes
                const scale =
                  0.9 / Math.max(boxWidth / fullWidth, boxHeight / fullHeight);
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

    // Build a set of resource nodes that have findings connected to them
    const resourcesWithFindings = new Set<string>();
    data.edges?.forEach((edge) => {
      const sourceId =
        typeof edge.source === "string"
          ? edge.source
          : (edge.source as GraphNode).id;
      const targetId =
        typeof edge.target === "string"
          ? edge.target
          : (edge.target as GraphNode).id;

      const sourceNode = nodeDataMap.get(sourceId);
      const targetNode = nodeDataMap.get(targetId);

      const sourceIsFinding = sourceNode?.labels.some((l) =>
        l.toLowerCase().includes("finding"),
      );
      const targetIsFinding = targetNode?.labels.some((l) =>
        l.toLowerCase().includes("finding"),
      );

      // If one end is a finding, the other is a resource with findings
      if (sourceIsFinding && !targetIsFinding) {
        resourcesWithFindings.add(targetId);
      }
      if (targetIsFinding && !sourceIsFinding) {
        resourcesWithFindings.add(sourceId);
      }
    });

    // Store in ref for use in selection updates
    resourcesWithFindingsRef.current = resourcesWithFindings;

    // Red alert color for resources with findings
    const ALERT_BORDER_COLOR = "#ef4444"; // Red 500

    // Add shapes - hexagons for findings, rounded pill shapes for resources
    nodeElements.each(function (d) {
      const group = select(this);
      const isFinding = d.data.labels.some((label) =>
        label.toLowerCase().includes("finding"),
      );
      const nodeColor = getNodeColor(d.data.labels, d.data.properties);
      const borderColor = getNodeBorderColor(d.data.labels, d.data.properties);
      const hasFindings = resourcesWithFindings.has(d.id);

      if (isFinding) {
        // Hexagon for findings - always has glow
        const w = HEXAGON_WIDTH;
        const h = HEXAGON_HEIGHT;
        const sideInset = w * 0.15;
        const hexPath = `
          M ${-w / 2 + sideInset} ${-h / 2}
          L ${w / 2 - sideInset} ${-h / 2}
          L ${w / 2} 0
          L ${w / 2 - sideInset} ${h / 2}
          L ${-w / 2 + sideInset} ${h / 2}
          L ${-w / 2} 0
          Z
        `;
        group
          .append("path")
          .attr("d", hexPath)
          .attr("fill", nodeColor)
          .attr("fill-opacity", 0.85)
          .attr(
            "stroke",
            d.id === selectedNodeId ? GRAPH_SELECTION_COLOR : borderColor,
          )
          .attr("stroke-width", d.id === selectedNodeId ? 3 : 2)
          .attr("filter", "url(#glow)")
          .attr("class", "node-shape");
      } else {
        // Check if this is an Internet node
        const isInternet = d.data.labels.some(
          (label) => label.toLowerCase() === "internet",
        );

        // Resources with findings get red border and red glow (even when selected)
        const strokeColor = hasFindings
          ? ALERT_BORDER_COLOR
          : d.id === selectedNodeId
            ? GRAPH_SELECTION_COLOR
            : borderColor;

        if (isInternet) {
          // Globe shape for Internet nodes - larger than regular nodes
          const radius = NODE_HEIGHT * 0.8;

          // Main circle
          group
            .append("circle")
            .attr("cx", 0)
            .attr("cy", 0)
            .attr("r", radius)
            .attr("fill", nodeColor)
            .attr("fill-opacity", 0.85)
            .attr("stroke", strokeColor)
            .attr(
              "stroke-width",
              hasFindings ? 2.5 : d.id === selectedNodeId ? 3 : 1.5,
            )
            .attr("filter", hasFindings ? "url(#redGlow)" : "url(#glow)")
            .attr("class", "node-shape");

          // Horizontal ellipse (equator)
          group
            .append("ellipse")
            .attr("cx", 0)
            .attr("cy", 0)
            .attr("rx", radius)
            .attr("ry", radius * 0.35)
            .attr("fill", "none")
            .attr("stroke", strokeColor)
            .attr("stroke-width", 1)
            .attr("stroke-opacity", 0.5);

          // Vertical ellipse (meridian)
          group
            .append("ellipse")
            .attr("cx", 0)
            .attr("cy", 0)
            .attr("rx", radius * 0.35)
            .attr("ry", radius)
            .attr("fill", "none")
            .attr("stroke", strokeColor)
            .attr("stroke-width", 1)
            .attr("stroke-opacity", 0.5);
        } else {
          // Rounded pill shape for other resources
          group
            .append("rect")
            .attr("x", -NODE_WIDTH / 2)
            .attr("y", -NODE_HEIGHT / 2)
            .attr("width", NODE_WIDTH)
            .attr("height", NODE_HEIGHT)
            .attr("rx", NODE_RADIUS)
            .attr("ry", NODE_RADIUS)
            .attr("fill", nodeColor)
            .attr("fill-opacity", 0.85)
            .attr("stroke", strokeColor)
            .attr(
              "stroke-width",
              hasFindings ? 2.5 : d.id === selectedNodeId ? 3 : 1.5,
            )
            .attr("filter", hasFindings ? "url(#redGlow)" : null)
            .attr("class", "node-shape");
        }
      }
    });

    // Store reference for updating selection later (select all shapes)
    const nodeShapes = nodeElements.selectAll(".node-shape");
    nodeShapesRef.current = nodeShapes as unknown as ReturnType<
      typeof select<SVGRectElement, NodeData>
    >;

    // Add label text - white text on all nodes (backgrounds are dark enough)
    nodeElements.each(function (d) {
      const group = select(this);
      const isFinding = d.data.labels.some((label) =>
        label.toLowerCase().includes("finding"),
      );

      // Create text container - white text with shadow for readability
      const textGroup = group
        .append("text")
        .attr("pointer-events", "none")
        .attr("text-anchor", "middle")
        .attr("dominant-baseline", "middle")
        .attr("fill", "#ffffff")
        .style("text-shadow", "0 1px 2px rgba(0,0,0,0.5)");

      if (isFinding) {
        // For findings: show check_title/name (severity is shown by color)
        const title = String(
          d.data.properties?.check_title ||
            d.data.properties?.name ||
            d.data.properties?.id ||
            "Finding",
        );
        const maxChars = 24;
        const displayTitle =
          title.length > maxChars
            ? title.substring(0, maxChars) + "..."
            : title;

        textGroup
          .append("tspan")
          .attr("x", 0)
          .attr("font-size", "11px")
          .attr("font-weight", "600")
          .text(displayTitle);
      } else {
        // For resources: show name with type below
        const name = String(
          d.data.properties?.name ||
            d.data.properties?.id ||
            (d.data.labels && d.data.labels.length > 0
              ? formatNodeLabel(d.data.labels[0])
              : "Unknown"),
        );
        const maxChars = 22;
        const displayName =
          name.length > maxChars ? name.substring(0, maxChars) + "..." : name;

        // Name
        textGroup
          .append("tspan")
          .attr("x", 0)
          .attr("dy", "-0.3em")
          .attr("font-size", "11px")
          .attr("font-weight", "600")
          .text(displayName);

        // Type label - slightly transparent white
        const type =
          d.data.labels && d.data.labels.length > 0
            ? formatNodeLabel(d.data.labels[0])
            : "";
        if (type) {
          textGroup
            .append("tspan")
            .attr("x", 0)
            .attr("dy", "1.3em")
            .attr("font-size", "9px")
            .attr("fill", "rgba(255,255,255,0.8)")
            .text(type);
        }
      }
    });

    // Add zoom behavior
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

    // Disable mouse wheel zoom (only allow programmatic zoom via buttons)
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
    // eslint-disable-next-line react-hooks/exhaustive-deps
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
