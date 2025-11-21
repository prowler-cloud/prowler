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

    // Calculate hierarchical layout (left to right flow - Mermaid LR style)
    // Build adjacency map to determine node levels
    // Container relationships (reverse direction for layout purposes)
    const containerRelations = new Set([
      "RUNS_IN",
      "BELONGS_TO",
      "LOCATED_IN",
      "PART_OF",
    ]);

    const adjacencyMap = new Map<string, string[]>();
    const reverseAdjacencyMap = new Map<string, string[]>();
    edges.forEach((edge) => {
      const source = edge.source;
      const target = edge.target;
      let sourceId =
        typeof source === "string"
          ? source
          : typeof source === "object" && source !== null
            ? (source as D3Node).id
            : "";
      let targetId =
        typeof target === "string"
          ? target
          : typeof target === "object" && target !== null
            ? (target as D3Node).id
            : "";

      // Reverse container relationships for proper hierarchy
      if (containerRelations.has(edge.type)) {
        [sourceId, targetId] = [targetId, sourceId];
      }

      if (!adjacencyMap.has(sourceId)) {
        adjacencyMap.set(sourceId, []);
      }
      adjacencyMap.get(sourceId)?.push(targetId);

      if (!reverseAdjacencyMap.has(targetId)) {
        reverseAdjacencyMap.set(targetId, []);
      }
      reverseAdjacencyMap.get(targetId)?.push(sourceId);
    });

    // Calculate node levels using longest path from root
    const incomingCount = new Map<string, number>();
    nodes.forEach((node) => incomingCount.set(node.id, 0));

    // Count incoming edges (respecting reversed container relationships)
    edges.forEach((edge) => {
      const source = edge.source;
      const target = edge.target;
      let targetId =
        typeof target === "string"
          ? target
          : typeof target === "object" && target !== null
            ? (target as D3Node).id
            : "";

      // If it's a container relationship, reverse the direction for counting
      if (containerRelations.has(edge.type)) {
        targetId =
          typeof source === "string"
            ? source
            : typeof source === "object" && source !== null
              ? (source as D3Node).id
              : "";
      }

      if (targetId) {
        incomingCount.set(targetId, (incomingCount.get(targetId) || 0) + 1);
      }
    });

    // Find root nodes (nodes with no incoming edges)
    const rootNodes: string[] = [];
    nodes.forEach((node) => {
      if (incomingCount.get(node.id) === 0) {
        rootNodes.push(node.id);
      }
    });

    // Calculate longest path from any root using DFS
    const levels = new Map<string, number>();
    const visited = new Set<string>();

    function calculateLongestPath(nodeId: string, currentDepth: number) {
      visited.add(nodeId);
      const existingLevel = levels.get(nodeId) || -1;

      // Always use the maximum depth (longest path)
      if (currentDepth > existingLevel) {
        levels.set(nodeId, currentDepth);
      }

      const neighbors = adjacencyMap.get(nodeId) || [];
      neighbors.forEach((neighborId) => {
        calculateLongestPath(neighborId, currentDepth + 1);
      });
    }

    // Start DFS from all root nodes
    rootNodes.forEach((rootId) => {
      calculateLongestPath(rootId, 0);
    });

    // Handle disconnected nodes or cycles
    nodes.forEach((node) => {
      if (!levels.has(node.id)) {
        // Place disconnected nodes at level 0
        levels.set(node.id, 0);
      }
    });

    // Group nodes by level and sort initially by node type to group similar nodes
    const nodesByLevel = new Map<number, D3Node[]>();
    nodes.forEach((node) => {
      const level = levels.get(node.id) || 0;
      if (!nodesByLevel.has(level)) {
        nodesByLevel.set(level, []);
      }
      nodesByLevel.get(level)?.push(node);
    });

    // Initial sorting: group nodes by type within each level for better starting point
    nodesByLevel.forEach((nodesInLevel, level) => {
      if (nodesInLevel.length > 1) {
        nodesInLevel.sort((a, b) => {
          // Get primary label
          const aLabel = a.labels[0]?.toLowerCase() || "";
          const bLabel = b.labels[0]?.toLowerCase() || "";

          // Sort findings to the end, resources at the beginning
          const aIsFinding = aLabel.includes("finding");
          const bIsFinding = bLabel.includes("finding");

          if (aIsFinding && !bIsFinding) return 1;
          if (!aIsFinding && bIsFinding) return -1;

          // Otherwise sort alphabetically by label
          return aLabel.localeCompare(bLabel);
        });
        nodesByLevel.set(level, nodesInLevel);
      }
    });

    // Sort nodes within each level to minimize edge crossings using barycenter method
    const maxLevel = Math.max(...Array.from(levels.values()));

    // Sort nodes within each level to minimize edge crossings
    // Use median heuristic which often works better than barycenter for complex graphs
    for (let iteration = 0; iteration < 4; iteration++) {
      // Forward pass (left to right) - position based on parents
      for (let level = 1; level <= maxLevel; level++) {
        const nodesInLevel = nodesByLevel.get(level) || [];

        if (nodesInLevel.length > 1) {
          const nodePositions = nodesInLevel.map((node, nodeIdx) => {
            const parents = reverseAdjacencyMap.get(node.id) || [];
            const parentPositions: number[] = [];

            // Get all parent positions
            parents.forEach((parentId) => {
              for (let prevLevel = 0; prevLevel < level; prevLevel++) {
                const levelNodes = nodesByLevel.get(prevLevel) || [];
                const pos = levelNodes.findIndex((n) => n.id === parentId);
                if (pos >= 0) {
                  parentPositions.push(pos);
                  break;
                }
              }
            });

            // Use median position if we have parents, otherwise keep current position
            let medianPos = nodeIdx;
            if (parentPositions.length > 0) {
              parentPositions.sort((a, b) => a - b);
              const mid = Math.floor(parentPositions.length / 2);
              medianPos =
                parentPositions.length % 2 === 0
                  ? (parentPositions[mid - 1] + parentPositions[mid]) / 2
                  : parentPositions[mid];
            }

            return { node, medianPos, originalIdx: nodeIdx };
          });

          // Sort by median position, keeping stable sort for ties
          nodePositions.sort(
            (a, b) =>
              a.medianPos - b.medianPos || a.originalIdx - b.originalIdx,
          );
          nodesByLevel.set(
            level,
            nodePositions.map((item) => item.node),
          );
        }
      }

      // Backward pass (right to left) - position based on children
      for (let level = maxLevel - 1; level >= 0; level--) {
        const nodesInLevel = nodesByLevel.get(level) || [];

        if (nodesInLevel.length > 1) {
          const nodePositions = nodesInLevel.map((node, nodeIdx) => {
            const children = adjacencyMap.get(node.id) || [];
            const childPositions: number[] = [];

            // Get all child positions
            children.forEach((childId) => {
              for (
                let nextLevel = level + 1;
                nextLevel <= maxLevel;
                nextLevel++
              ) {
                const levelNodes = nodesByLevel.get(nextLevel) || [];
                const pos = levelNodes.findIndex((n) => n.id === childId);
                if (pos >= 0) {
                  childPositions.push(pos);
                  break;
                }
              }
            });

            // Use median position if we have children, otherwise keep current position
            let medianPos = nodeIdx;
            if (childPositions.length > 0) {
              childPositions.sort((a, b) => a - b);
              const mid = Math.floor(childPositions.length / 2);
              medianPos =
                childPositions.length % 2 === 0
                  ? (childPositions[mid - 1] + childPositions[mid]) / 2
                  : childPositions[mid];
            }

            return { node, medianPos, originalIdx: nodeIdx };
          });

          // Sort by median position, keeping stable sort for ties
          nodePositions.sort(
            (a, b) =>
              a.medianPos - b.medianPos || a.originalIdx - b.originalIdx,
          );
          nodesByLevel.set(
            level,
            nodePositions.map((item) => item.node),
          );
        }
      }
    }

    // Calculate spacing - leave margin on left for root nodes
    const leftMargin = 150;
    const rightMargin = 150;
    const availableWidth = width - leftMargin - rightMargin;
    const levelSpacing =
      maxLevel > 0 ? availableWidth / maxLevel : availableWidth;

    // Create force simulation with hierarchical left-to-right layout (Mermaid LR style)
    const simulation = d3
      .forceSimulation(nodes)
      .force(
        "link",
        d3
          .forceLink<D3Node, D3Link>(edges)
          .id((d) => d.id)
          .distance(levelSpacing * 0.7)
          .strength(0.2),
      )
      .force("charge", d3.forceManyBody().strength(-600))
      .force("collision", d3.forceCollide<D3Node>().radius(85))
      // Very strong horizontal force to maintain strict columns
      .force(
        "x",
        d3
          .forceX<D3Node>()
          .x((d) => {
            const level = levels.get(d.id) || 0;
            return leftMargin + levelSpacing * level;
          })
          .strength(0.8),
      )
      // Strong vertical force to distribute nodes within their level
      .force(
        "y",
        d3
          .forceY<D3Node>()
          .y((d) => {
            const level = levels.get(d.id) || 0;
            const nodesInLevel = nodesByLevel.get(level) || [];
            const indexInLevel = nodesInLevel.findIndex((n) => n.id === d.id);
            const verticalSpacing = height / (nodesInLevel.length + 1);
            return verticalSpacing * (indexInLevel + 1);
          })
          .strength(0.7),
      )
      .velocityDecay(0.4)
      .alphaDecay(0.015)
      .alphaMin(0.001);

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
      .attr("cursor", "pointer");

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
        onNodeClick?.(d);
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
        const type =
          d.labels && d.labels.length > 0
            ? formatNodeLabel(d.labels[0])
            : "Unknown";
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
