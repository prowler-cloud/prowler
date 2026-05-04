/**
 * Export utilities for attack path graphs
 * React Flow renders HTML, so PNG export uses modern-screenshot + RF viewport math
 */

import { getViewportForBounds, type Rect } from "@xyflow/react";
import { domToPng } from "modern-screenshot";

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

// Export target dimensions — fixed so bounds math is deterministic across zoom levels
const EXPORT_IMAGE_WIDTH = 1920;
const EXPORT_IMAGE_HEIGHT = 1080;
const EXPORT_MIN_ZOOM = 0.2;
const EXPORT_MAX_ZOOM = 2;
const EXPORT_PADDING = 0.1;
const EXPORT_BACKGROUND = "#1c1917";

/**
 * Export graph as PNG via modern-screenshot.
 *
 * Receives pre-computed node bounds (use `GraphHandle.getNodesBounds()` so the
 * React Flow instance's `nodeLookup` is honored for sub-flows). Then uses
 * `getViewportForBounds()` to produce a viewport transform that fits all nodes
 * inside the export canvas regardless of the user's current zoom/pan, and
 * applies it to `.react-flow__viewport` before rasterizing.
 */
export const exportGraphAsPNG = async (
  containerElement: HTMLDivElement | null,
  bounds: Rect | null,
  filename: string = "attack-path-graph.png",
) => {
  if (!containerElement) {
    throw new Error("Graph container not mounted");
  }

  const viewportElement = containerElement.querySelector<HTMLElement>(
    ".react-flow__viewport",
  );
  if (!viewportElement) {
    throw new Error("React Flow viewport not found in container");
  }

  if (!bounds) {
    throw new Error("No nodes to export");
  }

  const viewport = getViewportForBounds(
    bounds,
    EXPORT_IMAGE_WIDTH,
    EXPORT_IMAGE_HEIGHT,
    EXPORT_MIN_ZOOM,
    EXPORT_MAX_ZOOM,
    EXPORT_PADDING,
  );

  try {
    const dataUrl = await domToPng(viewportElement, {
      backgroundColor: EXPORT_BACKGROUND,
      width: EXPORT_IMAGE_WIDTH,
      height: EXPORT_IMAGE_HEIGHT,
      style: {
        width: `${EXPORT_IMAGE_WIDTH}px`,
        height: `${EXPORT_IMAGE_HEIGHT}px`,
        transform: `translate(${viewport.x}px, ${viewport.y}px) scale(${viewport.zoom})`,
      },
    });
    downloadDataUrl(dataUrl, filename);
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
