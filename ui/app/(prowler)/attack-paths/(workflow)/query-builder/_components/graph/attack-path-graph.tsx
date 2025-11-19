"use client";

import * as d3 from "d3";
import {
  forwardRef,
  useEffect,
  useImperativeHandle,
  useRef,
  useState,
} from "react";

import type {
  AttackPathGraphData,
  GraphNode,
  GraphNodePropertyValue,
} from "@/types/attack-paths";

import {
  getNodeColor,
  GRAPH_EDGE_COLOR,
  GRAPH_SELECTION_COLOR,
} from "../../_lib/graph-colors";

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
  ref?: React.Ref<AttackPathGraphRef>;
}

interface D3Node extends d3.SimulationNodeDatum {
  id: string;
  labels: string[];
  properties: Record<string, GraphNodePropertyValue>;
  x?: number;
  y?: number;
}

interface D3Link extends d3.SimulationLinkDatum<D3Node> {
  id: string;
  type: string;
}

/**
 * Helper function to format camelCase labels to space-separated text
 * e.g., "ProwlerFinding" -> "Prowler Finding", "AWSAccount" -> "Aws Account"
 */
function formatNodeLabel(label: string): string {
  return label
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .replace(/([a-z\d])([A-Z])/g, "$1 $2")
    .trim()
    .split(" ")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(" ");
}

/**
 * Node type to icon unicode mapping
 */
const NODE_TYPE_ICONS = {
  prowlerfinding: "⚠",
  awsaccount: "☁",
  ec2instance: "🖥",
  s3bucket: "💾",
  iamrole: "🔑",
  default: "●",
} as const;

/**
 * Get icon for node based on label type
 * Maps node types to unicode emoji icons
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
 * D3 Force-directed graph visualization for attack paths
 * Renders interactive graph with nodes and edges
 */
const AttackPathGraphComponent = forwardRef<
  AttackPathGraphRef,
  AttackPathGraphProps
>(({ data, onNodeClick, selectedNodeId }, ref) => {
  const svgRef = useRef<SVGSVGElement>(null);
  const [zoomLevel, setZoomLevel] = useState(1);
  const zoomBehaviorRef = useRef<d3.ZoomBehavior<
    SVGSVGElement,
    unknown
  > | null>(null);
  const containerRef = useRef<d3.Selection<
    SVGGElement,
    unknown,
    HTMLElement,
    unknown
  > | null>(null);
  const svgSelectionRef = useRef<d3.Selection<
    SVGSVGElement,
    unknown,
    HTMLElement,
    unknown
  > | null>(null);
  /** Track whether graph has been auto-centered to avoid repeated centering as simulation settles */
  const hasAutocenteredRef = useRef(false);
  /** Track drag state to distinguish node clicks from drag interactions */
  const draggedRef = useRef(false);

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
            d3.zoomIdentity.translate(tx, ty).scale(scale),
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
    d3.select(svgRef.current).selectAll("*").remove();

    // Create SVG
    const svg = d3
      .select(svgRef.current)
      .attr("width", width)
      .attr("height", height)
      .attr("viewBox", [0, 0, width, height]);

    // Create container for zoom/pan
    const container = svg.append("g") as unknown as d3.Selection<
      SVGGElement,
      unknown,
      HTMLElement,
      unknown
    >;
    containerRef.current = container;
    svgSelectionRef.current = svg as unknown as d3.Selection<
      SVGSVGElement,
      unknown,
      HTMLElement,
      unknown
    >;

    // Prepare data: convert nodes and create edges
    const nodes: D3Node[] = data.nodes.map((node) => ({
      ...node,
      id: node.id,
      labels: node.labels,
      properties: node.properties,
      x: undefined,
      y: undefined,
    }));

    // Create edges from data or generate from relationships if available
    let edges: D3Link[] = [];
    if (data.edges && Array.isArray(data.edges)) {
      edges = data.edges
        .map((edge, idx) => {
          const sourceId =
            typeof edge.source === "string"
              ? edge.source
              : typeof edge.source === "object" && edge.source !== null
                ? (edge.source as GraphNode).id
                : (edge.properties?.source as string);

          const targetId =
            typeof edge.target === "string"
              ? edge.target
              : typeof edge.target === "object" && edge.target !== null
                ? (edge.target as GraphNode).id
                : (edge.properties?.target as string);

          // Skip edges with invalid source or target
          if (!sourceId || !targetId) {
            return null;
          }

          return {
            id: edge.id || `edge-${idx}`,
            source: sourceId,
            target: targetId,
            type: edge.type || "relates_to",
          };
        })
        .filter((edge) => edge !== null) as D3Link[];
    }

    // Create force simulation
    const simulation = d3
      .forceSimulation(nodes)
      .force(
        "link",
        d3
          .forceLink<D3Node, D3Link>(edges)
          .id((d) => d.id)
          .distance(150),
      )
      .force("charge", d3.forceManyBody().strength(-400))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide<D3Node>().radius(65));

    // Create links
    const link = container
      .selectAll("line")
      .data(edges)
      .enter()
      .append("line")
      .attr("stroke", GRAPH_EDGE_COLOR)
      .attr("stroke-opacity", 0.6)
      .attr("stroke-width", 2);

    // Create node groups
    const nodeGroup = container
      .selectAll("g.node")
      .data(nodes)
      .enter()
      .append("g")
      .attr("class", "node")
      .attr("cursor", "pointer")
      .call(
        d3
          .drag<SVGGElement, D3Node>()
          .on("start", dragStarted)
          .on("drag", dragged)
          .on("end", dragEnded),
      );

    // Add tooltip (title element for native SVG tooltips)
    nodeGroup.append("title").text((d: D3Node): string => {
      // Show the first node label (full text for tooltip)
      if (d.labels && d.labels.length > 0) {
        return formatNodeLabel(d.labels[0]);
      }
      return d.id;
    });

    // Add circles for nodes
    nodeGroup
      .append("circle")
      .attr("r", 45)
      .attr("fill", (d: D3Node) => getNodeColor(d.labels))
      .attr("opacity", 0.8)
      .on("click", (event: PointerEvent, d: D3Node) => {
        event.stopPropagation();
        // Only trigger click if no drag occurred
        if (!draggedRef.current) {
          onNodeClick?.(d);
        }
        draggedRef.current = false;
      });

    // Add label text group containing icon, type, and ID - centered in node
    const textGroups = nodeGroup.append("text").attr("pointer-events", "none");

    // First line: Node type icon
    textGroups
      .append("tspan")
      .attr("x", 0)
      .attr("dy", "-0.4em")
      .attr("font-size", "16px")
      .attr("fill", "white")
      .attr("opacity", 0.9)
      .attr("text-anchor", "middle")
      .text((d: D3Node): string => getNodeTypeIcon(d.labels));

    // Second line: Node type
    textGroups
      .append("tspan")
      .attr("x", 0)
      .attr("dy", "1.3em")
      .attr("font-size", "10px")
      .attr("fill", "white")
      .attr("font-weight", "bold")
      .attr("text-anchor", "middle")
      .text((d: D3Node): string => {
        const type = d.labels && d.labels.length > 0 ? d.labels[0] : "Unknown";
        return type.length > 16 ? type.substring(0, 16) + "." : type;
      });

    // Third line: Severity (if available) or ID
    textGroups
      .append("tspan")
      .attr("x", 0)
      .attr("dy", "1.2em")
      .attr("font-size", "9px")
      .attr("fill", "white")
      .attr("text-anchor", "middle")
      .text((d: D3Node): string => {
        const severity = d.properties?.severity;
        return severity ? String(severity) : d.id.substring(0, 8);
      });

    // Add zoom behavior
    const zoom = d3
      .zoom<SVGSVGElement, unknown>()
      .on("zoom", (event: d3.D3ZoomEvent<SVGSVGElement, unknown>) => {
        const transform = event.transform;
        container.attr("transform", transform.toString());
        setZoomLevel(transform.k);
      });
    zoomBehaviorRef.current = zoom;

    svg.call(zoom);

    // Disable scroll/wheel zoom, keep only programmatic zoom from controls
    svg.on("wheel.zoom", null);

    // Reset auto-center flag for new data
    hasAutocenteredRef.current = false;

    // Function to center the graph
    const centerGraph = () => {
      if (
        svgSelectionRef.current &&
        zoomBehaviorRef.current &&
        containerRef.current &&
        !hasAutocenteredRef.current
      ) {
        hasAutocenteredRef.current = true;
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
          d3.zoomIdentity.translate(tx, ty).scale(scale),
        );
      }
    };

    // Helper to safely get node coordinates from link source/target
    const getSourceX = (d: D3Link): number => {
      const source = d.source as D3Node;
      return source.x || 0;
    };
    const getSourceY = (d: D3Link): number => {
      const source = d.source as D3Node;
      return source.y || 0;
    };
    const getTargetX = (d: D3Link): number => {
      const target = d.target as D3Node;
      return target.x || 0;
    };
    const getTargetY = (d: D3Link): number => {
      const target = d.target as D3Node;
      return target.y || 0;
    };

    // Update positions on simulation tick
    simulation.on("tick", (): void => {
      link
        .attr("x1", getSourceX)
        .attr("y1", getSourceY)
        .attr("x2", getTargetX)
        .attr("y2", getTargetY);

      nodeGroup.attr(
        "transform",
        (d: D3Node) => `translate(${d.x || 0},${d.y || 0})`,
      );

      // Center graph once when simulation starts settling
      if (simulation.alpha() < 0.5 && !hasAutocenteredRef.current) {
        centerGraph();
      }
    });

    // Drag functions
    function dragStarted(event: d3.D3DragEvent<SVGGElement, D3Node, D3Node>) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      event.subject.fx = event.subject.x;
      event.subject.fy = event.subject.y;
    }

    function dragged(event: d3.D3DragEvent<SVGGElement, D3Node, D3Node>) {
      draggedRef.current = true;
      event.subject.fx = event.x;
      event.subject.fy = event.y;
    }

    function dragEnded(event: d3.D3DragEvent<SVGGElement, D3Node, D3Node>) {
      if (!event.active) simulation.alphaTarget(0);
      event.subject.fx = null;
      event.subject.fy = null;
    }

    return () => {
      simulation.stop();
    };
  }, [data, onNodeClick]);

  // Separate effect to update selection highlight without rebuilding graph
  useEffect(() => {
    if (!containerRef.current) return;

    const updateSelection = (d: D3Node) => {
      return d.id === selectedNodeId ? GRAPH_SELECTION_COLOR : "none";
    };

    const updateWidth = (d: D3Node) => {
      return d.id === selectedNodeId ? 3 : 0;
    };

    const nodeGroup = containerRef.current.selectAll<SVGCircleElement, D3Node>(
      "g.node",
    );
    nodeGroup
      .selectAll<SVGCircleElement, D3Node>("circle")
      .attr("stroke", updateSelection)
      .attr("stroke-width", updateWidth);
  }, [selectedNodeId]);

  return (
    <svg
      ref={svgRef}
      className="dark:bg-bg-neutral-secondary bg-bg-neutral-secondary h-full w-full rounded-lg"
    />
  );
});

AttackPathGraphComponent.displayName = "AttackPathGraph";

export const AttackPathGraph = AttackPathGraphComponent;
