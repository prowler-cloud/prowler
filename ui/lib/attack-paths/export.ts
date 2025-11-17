/**
 * Export utilities for attack path graphs
 * Handles exporting graph visualization to various formats
 */

/**
 * Helper function to download a blob as a file
 * @param blob The blob to download
 * @param filename The name of the file
 */
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

/**
 * Export graph as SVG image
 * @param svgElement The SVG element to export
 * @param filename The name of the file to download
 */
export const exportGraphAsSVG = (
  svgElement: SVGSVGElement | null,
  filename: string = "attack-path-graph.svg",
) => {
  if (!svgElement) return;

  try {
    const svgData = new XMLSerializer().serializeToString(svgElement);
    const blob = new Blob([svgData], { type: "image/svg+xml" });
    downloadBlob(blob, filename);
  } catch (error) {
    console.error("Failed to export graph as SVG:", error);
    throw new Error("Failed to export graph");
  }
};

/**
 * Export graph as PNG image
 * @param svgElement The SVG element to export
 * @param filename The name of the file to download
 */
export const exportGraphAsPNG = async (
  svgElement: SVGSVGElement | null,
  filename: string = "attack-path-graph.png",
) => {
  if (!svgElement) return;

  try {
    const svgData = new XMLSerializer().serializeToString(svgElement);
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d") as CanvasRenderingContext2D;

    if (!ctx) throw new Error("Could not get canvas context");

    const svg = new Image();
    svg.onload = () => {
      canvas.width = svg.width;
      canvas.height = svg.height;
      ctx.drawImage(svg, 0, 0);
      canvas.toBlob((blob) => {
        if (blob) {
          downloadBlob(blob, filename);
        }
      });
    };
    svg.onerror = () => {
      throw new Error("Failed to load SVG for PNG conversion");
    };
    svg.src = `data:image/svg+xml;base64,${btoa(svgData)}`;
  } catch (error) {
    console.error("Failed to export graph as PNG:", error);
    throw new Error("Failed to export graph");
  }
};

/**
 * Export graph data as JSON
 * @param graphData The graph data to export
 * @param filename The name of the file to download
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
