/**
 * Export utilities for attack path graphs.
 *
 * React Flow DOM screenshotting proved unreliable in-app, so PNG export draws a
 * deterministic canvas from the same graph data + Dagre layout used by the UI.
 */

import type { Rect } from "@xyflow/react";

import type { AttackPathGraphData, GraphEdge } from "@/types/attack-paths";

import { getNodeLabelLines } from "../_components/graph/nodes/node-label-lines";
import { truncateLabel } from "./format";
import {
  getNodeBorderColor,
  getNodeColor,
  GRAPH_ALERT_BORDER_COLOR,
  GRAPH_EDGE_COLOR_DARK,
} from "./graph-colors";
import { layoutWithDagre } from "./layout";
import { resolveNodeVisual } from "./node-visuals";

interface ExportGraphOptions {
  expandedResources?: ReadonlySet<string>;
  isFilteredView?: boolean;
  selectedNodeId?: string | null;
}

interface Point {
  x: number;
  y: number;
}

const EXPORT_IMAGE_WIDTH = 1920;
const EXPORT_IMAGE_HEIGHT = 1080;
const EXPORT_BACKGROUND = "#1c1917";
const EXPORT_PADDING = 96;
const DOT_SPACING = 32;
const BADGE_RADIUS = 22;
const BADGE_CENTER_Y = 26;
const GLOW_RADIUS = 30;
const LABEL_Y = 66;
const LABEL_LINE_HEIGHT = 13;
const TYPE_Y = 118;
const RESOURCE_NAME_MAX_CHARS = 16;
const FINDING_TITLE_MAX_CHARS = 18;
const NODE_LABEL_MAX_LINES = 4;

const downloadBlob = (blob: Blob, filename: string) => {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
};

const downloadDataUrl = (dataUrl: string, filename: string) => {
  const link = document.createElement("a");
  link.href = dataUrl;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
};

const isFindingNode = (labels: string[]) =>
  labels.some((label) => label.toLowerCase().includes("finding"));

const getGraphEdges = (graphData: AttackPathGraphData): GraphEdge[] => {
  if (graphData.edges?.length) return graphData.edges;

  return (graphData.relationships ?? []).map((relationship) => ({
    id: relationship.id,
    source: relationship.source,
    target: relationship.target,
    type: relationship.label,
    properties: relationship.properties,
  }));
};

const getVisibleGraphData = (
  graphData: AttackPathGraphData,
  options: ExportGraphOptions = {},
): AttackPathGraphData => {
  if (options.isFilteredView) return graphData;

  const edges = getGraphEdges(graphData);
  const expandedResources = options.expandedResources ?? new Set<string>();
  const nodeById = new Map(graphData.nodes.map((node) => [node.id, node]));
  const hiddenFindingIds = new Set<string>();

  graphData.nodes.forEach((node) => {
    if (!isFindingNode(node.labels)) return;

    const connectedResources = edges
      .flatMap((edge) => {
        if (edge.source === node.id) return [edge.target];
        if (edge.target === node.id) return [edge.source];
        return [];
      })
      .filter((id) => {
        const connectedNode = nodeById.get(id);
        return connectedNode && !isFindingNode(connectedNode.labels);
      });

    const hasExpandedResource = connectedResources.some((resourceId) =>
      expandedResources.has(resourceId),
    );
    if (connectedResources.length > 0 && !hasExpandedResource) {
      hiddenFindingIds.add(node.id);
    }
  });

  return {
    nodes: graphData.nodes.filter((node) => !hiddenFindingIds.has(node.id)),
    edges: edges.filter(
      (edge) =>
        !hiddenFindingIds.has(edge.source) &&
        !hiddenFindingIds.has(edge.target),
    ),
  };
};

const getResourcesWithFindings = (
  sourceGraphData: AttackPathGraphData,
  visibleGraphData: AttackPathGraphData,
) => {
  const visibleNodeIds = new Set(visibleGraphData.nodes.map((node) => node.id));
  const sourceNodeById = new Map(
    sourceGraphData.nodes.map((node) => [node.id, node]),
  );
  const findingNodeIds = new Set(
    sourceGraphData.nodes
      .filter((node) => isFindingNode(node.labels))
      .map((node) => node.id),
  );
  const resourcesWithFindings = new Set<string>();

  getGraphEdges(sourceGraphData).forEach((edge) => {
    const sourceIsFinding = findingNodeIds.has(edge.source);
    const targetIsFinding = findingNodeIds.has(edge.target);
    const sourceNode = sourceNodeById.get(edge.source);
    const targetNode = sourceNodeById.get(edge.target);

    if (
      sourceIsFinding &&
      targetNode &&
      !isFindingNode(targetNode.labels) &&
      visibleNodeIds.has(edge.target)
    ) {
      resourcesWithFindings.add(edge.target);
    }

    if (
      targetIsFinding &&
      sourceNode &&
      !isFindingNode(sourceNode.labels) &&
      visibleNodeIds.has(edge.source)
    ) {
      resourcesWithFindings.add(edge.source);
    }
  });

  return resourcesWithFindings;
};

const getFittedLayout = (graphData: AttackPathGraphData) => {
  const { rfNodes, rfEdges } = layoutWithDagre(
    graphData.nodes,
    getGraphEdges(graphData),
  );

  if (rfNodes.length === 0) {
    throw new Error("No nodes to export");
  }

  const minX = Math.min(...rfNodes.map((node) => node.position.x));
  const minY = Math.min(...rfNodes.map((node) => node.position.y));
  const maxX = Math.max(
    ...rfNodes.map((node) => node.position.x + (node.width ?? 0)),
  );
  const maxY = Math.max(
    ...rfNodes.map((node) => node.position.y + (node.height ?? 0)),
  );
  const graphWidth = Math.max(maxX - minX, 1);
  const graphHeight = Math.max(maxY - minY, 1);
  const scale = Math.min(
    (EXPORT_IMAGE_WIDTH - EXPORT_PADDING * 2) / graphWidth,
    (EXPORT_IMAGE_HEIGHT - EXPORT_PADDING * 2) / graphHeight,
    2,
  );
  const offsetX = (EXPORT_IMAGE_WIDTH - graphWidth * scale) / 2 - minX * scale;
  const offsetY =
    (EXPORT_IMAGE_HEIGHT - graphHeight * scale) / 2 - minY * scale;

  const toExportPoint = (x: number, y: number): Point => ({
    x: x * scale + offsetX,
    y: y * scale + offsetY,
  });

  return { rfNodes, rfEdges, toExportPoint };
};

const drawBackground = (context: CanvasRenderingContext2D) => {
  context.fillStyle = EXPORT_BACKGROUND;
  context.fillRect(0, 0, EXPORT_IMAGE_WIDTH, EXPORT_IMAGE_HEIGHT);

  context.fillStyle = "rgba(68, 64, 60, 0.55)";
  for (let x = 2; x < EXPORT_IMAGE_WIDTH; x += DOT_SPACING) {
    for (let y = 2; y < EXPORT_IMAGE_HEIGHT; y += DOT_SPACING) {
      context.beginPath();
      context.arc(x, y, 1.4, 0, Math.PI * 2);
      context.fill();
    }
  }
};

const movePointToward = (from: Point, to: Point, distance: number): Point => {
  const dx = to.x - from.x;
  const dy = to.y - from.y;
  const length = Math.hypot(dx, dy);
  if (length === 0) return from;

  return {
    x: from.x + (dx / length) * distance,
    y: from.y + (dy / length) * distance,
  };
};

const drawArrowHead = (
  context: CanvasRenderingContext2D,
  from: Point,
  to: Point,
) => {
  const angle = Math.atan2(to.y - from.y, to.x - from.x);
  const size = 10;

  context.beginPath();
  context.moveTo(to.x, to.y);
  context.lineTo(
    to.x - size * Math.cos(angle - Math.PI / 6),
    to.y - size * Math.sin(angle - Math.PI / 6),
  );
  context.lineTo(
    to.x - size * Math.cos(angle + Math.PI / 6),
    to.y - size * Math.sin(angle + Math.PI / 6),
  );
  context.closePath();
  context.fill();
};

const drawEdges = (
  context: CanvasRenderingContext2D,
  edges: ReturnType<typeof layoutWithDagre>["rfEdges"],
  getNodeCenter: (id: string) => Point | null,
) => {
  context.strokeStyle = GRAPH_EDGE_COLOR_DARK;
  context.fillStyle = GRAPH_EDGE_COLOR_DARK;
  context.globalAlpha = 0.72;
  context.lineWidth = 2;

  edges.forEach((edge) => {
    const source = getNodeCenter(edge.source);
    const target = getNodeCenter(edge.target);
    if (!source || !target) return;

    const start = movePointToward(source, target, BADGE_RADIUS);
    const end = movePointToward(target, source, BADGE_RADIUS + 8);
    const midX = (start.x + end.x) / 2;
    context.setLineDash(
      edge.className?.includes("finding-edge") ? [10, 8] : [],
    );
    context.beginPath();
    context.moveTo(start.x, start.y);
    context.bezierCurveTo(midX, start.y, midX, end.y, end.x, end.y);
    context.stroke();
    context.setLineDash([]);
    drawArrowHead(context, start, end);
  });

  context.globalAlpha = 1;
};

const drawShieldIcon = (
  context: CanvasRenderingContext2D,
  x: number,
  y: number,
) => {
  context.beginPath();
  context.moveTo(x, y - 12);
  context.quadraticCurveTo(x + 8, y - 8, x + 12, y - 8);
  context.lineTo(x + 10, y + 3);
  context.quadraticCurveTo(x + 8, y + 11, x, y + 14);
  context.quadraticCurveTo(x - 8, y + 11, x - 10, y + 3);
  context.lineTo(x - 12, y - 8);
  context.quadraticCurveTo(x - 8, y - 8, x, y - 12);
  context.stroke();
  context.beginPath();
  context.moveTo(x - 5, y);
  context.lineTo(x - 1, y + 4);
  context.lineTo(x + 7, y - 5);
  context.stroke();
};

const drawKeyIcon = (
  context: CanvasRenderingContext2D,
  x: number,
  y: number,
) => {
  context.beginPath();
  context.arc(x - 6, y - 2, 5, 0, Math.PI * 2);
  context.moveTo(x - 1, y - 2);
  context.lineTo(x + 12, y - 2);
  context.moveTo(x + 8, y - 2);
  context.lineTo(x + 8, y + 5);
  context.moveTo(x + 12, y - 2);
  context.lineTo(x + 12, y + 3);
  context.stroke();
};

const drawFindingIcon = (
  context: CanvasRenderingContext2D,
  x: number,
  y: number,
) => {
  context.beginPath();
  context.moveTo(x, y - 13);
  context.lineTo(x + 13, y + 10);
  context.lineTo(x - 13, y + 10);
  context.closePath();
  context.stroke();
  context.font = "700 18px sans-serif";
  context.textAlign = "center";
  context.textBaseline = "middle";
  context.fillText("!", x, y + 3);
};

const drawNodeIcon = (
  context: CanvasRenderingContext2D,
  x: number,
  y: number,
  category: string,
  description: string,
) => {
  const lowerDescription = description.toLowerCase();
  context.save();
  context.strokeStyle = "#ffffff";
  context.fillStyle = "#ffffff";
  context.lineWidth = 2.2;
  context.lineCap = "round";
  context.lineJoin = "round";

  if (category === "finding") {
    drawFindingIcon(context, x, y);
  } else if (lowerDescription.includes("policy statement")) {
    context.font = "700 24px monospace";
    context.textAlign = "center";
    context.textBaseline = "middle";
    context.fillText("{}", x, y + 1);
  } else if (lowerDescription.includes("policy")) {
    drawKeyIcon(context, x, y);
  } else if (category === "identity" || lowerDescription.includes("role")) {
    drawShieldIcon(context, x, y);
  } else if (category === "account") {
    context.font = "700 11px sans-serif";
    context.textAlign = "center";
    context.textBaseline = "middle";
    context.fillText("AWS", x, y + 1);
  } else {
    context.font = "700 14px sans-serif";
    context.textAlign = "center";
    context.textBaseline = "middle";
    context.fillText(
      description
        .split(" ")
        .map((word) => word[0])
        .join("")
        .slice(0, 2)
        .toUpperCase(),
      x,
      y + 1,
    );
  }

  context.restore();
};

const drawNode = (
  context: CanvasRenderingContext2D,
  graphNode: AttackPathGraphData["nodes"][number],
  center: Point,
  options: { hasFindings: boolean; selected: boolean },
) => {
  const isFinding = isFindingNode(graphNode.labels);
  const visual = resolveNodeVisual(graphNode);
  const fill = getNodeColor(graphNode.labels, graphNode.properties);
  const stroke = options.hasFindings
    ? GRAPH_ALERT_BORDER_COLOR
    : getNodeBorderColor(graphNode.labels, graphNode.properties);
  const glowOpacity = options.selected
    ? 0.34
    : isFinding
      ? 0.28
      : options.hasFindings
        ? 0.26
        : 0;
  const strokeWidth = options.selected
    ? 4
    : options.hasFindings
      ? 3
      : isFinding
        ? 2.5
        : 1.5;

  if (glowOpacity > 0) {
    context.fillStyle = stroke;
    context.globalAlpha = glowOpacity / 2;
    context.beginPath();
    context.arc(center.x, center.y, GLOW_RADIUS, 0, Math.PI * 2);
    context.fill();
    context.globalAlpha = 1;
  }

  context.fillStyle = fill;
  context.strokeStyle = stroke;
  context.lineWidth = strokeWidth;
  context.beginPath();
  context.arc(center.x, center.y, BADGE_RADIUS, 0, Math.PI * 2);
  context.fill();
  context.stroke();

  const typeLabel = truncateLabel(visual.description, 22);
  drawNodeIcon(context, center.x, center.y, visual.category, typeLabel);

  context.fillStyle = "#ffffff";
  context.textAlign = "center";
  context.textBaseline = "middle";
  context.font = "600 11px sans-serif";
  const labelMaxChars = isFinding
    ? FINDING_TITLE_MAX_CHARS
    : RESOURCE_NAME_MAX_CHARS;

  getNodeLabelLines(
    visual.displayName,
    labelMaxChars,
    NODE_LABEL_MAX_LINES,
  ).forEach((line, index) => {
    context.fillText(
      line,
      center.x,
      center.y + (LABEL_Y - BADGE_CENTER_Y) + index * LABEL_LINE_HEIGHT,
      150,
    );
  });

  context.fillStyle = "rgba(255,255,255,0.82)";
  context.font = "9px sans-serif";
  context.fillText(
    typeLabel,
    center.x,
    center.y + (TYPE_Y - BADGE_CENTER_Y),
    150,
  );
};

const renderGraphToPngDataUrl = (
  graphData: AttackPathGraphData,
  options?: ExportGraphOptions,
) => {
  const canvas = document.createElement("canvas");
  canvas.width = EXPORT_IMAGE_WIDTH;
  canvas.height = EXPORT_IMAGE_HEIGHT;
  const context = canvas.getContext("2d");
  if (!context) throw new Error("Canvas not available");

  const visibleGraphData = getVisibleGraphData(graphData, options);
  const resourcesWithFindings = getResourcesWithFindings(
    graphData,
    visibleGraphData,
  );
  const { rfNodes, rfEdges, toExportPoint } = getFittedLayout(visibleGraphData);
  const nodeById = new Map(rfNodes.map((node) => [node.id, node]));
  const getNodeCenter = (id: string) => {
    const node = nodeById.get(id);
    if (!node) return null;
    return toExportPoint(
      node.position.x + (node.width ?? 0) / 2,
      node.position.y + BADGE_CENTER_Y,
    );
  };

  drawBackground(context);
  drawEdges(context, rfEdges, getNodeCenter);
  rfNodes.forEach((rfNode) => {
    const center = getNodeCenter(rfNode.id);
    if (!center) return;

    drawNode(context, rfNode.data.graphNode, center, {
      hasFindings: resourcesWithFindings.has(rfNode.id),
      selected: options?.selectedNodeId === rfNode.id,
    });
  });

  return canvas.toDataURL("image/png");
};

/**
 * Export graph as PNG using graph data instead of DOM rasterization.
 */
export const exportGraphAsPNG = async (
  containerElement: HTMLDivElement | null,
  bounds: Rect | null,
  filename: string = "attack-path-graph.png",
  graphData?: AttackPathGraphData | null,
  options?: ExportGraphOptions,
) => {
  if (!containerElement) {
    throw new Error("Graph container not mounted");
  }

  if (!containerElement.querySelector(".react-flow")) {
    throw new Error("React Flow root not found in container");
  }

  if (!containerElement.querySelector(".react-flow__viewport")) {
    throw new Error("React Flow viewport not found in container");
  }

  if (!bounds || !graphData?.nodes.length) {
    throw new Error("No nodes to export");
  }

  try {
    downloadDataUrl(renderGraphToPngDataUrl(graphData, options), filename);
  } catch (error) {
    console.error("Failed to export graph as PNG:", error);
    throw new Error("Failed to export graph");
  }
};

/**
 * Export graph data as JSON (format-agnostic — does not depend on DOM rendering).
 */
export const exportGraphAsJSON = (
  graphData: Record<string, unknown>,
  filename: string = "attack-path-graph.json",
) => {
  try {
    const jsonString = JSON.stringify(graphData, null, 2);
    const blob = new Blob([jsonString], { type: "application/json" });
    downloadBlob(blob, filename);
  } catch (error) {
    console.error("Failed to export graph as JSON:", error);
    throw new Error("Failed to export graph");
  }
};
