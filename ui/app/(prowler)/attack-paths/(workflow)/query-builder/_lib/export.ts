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
    // Clone the SVG element to avoid modifying the original
    const clonedSvg = svgElement.cloneNode(true) as SVGSVGElement;

    // Find the main container group (first g element with transform)
    const containerGroup = clonedSvg.querySelector("g");
    if (!containerGroup) {
      throw new Error("Could not find graph container");
    }

    // Get the bounding box of the actual graph content
    // We need to get it from the original SVG since cloned elements don't have computed geometry
    const originalContainer = svgElement.querySelector("g");
    if (!originalContainer) {
      throw new Error("Could not find original graph container");
    }

    const bbox = originalContainer.getBBox();

    // Add padding around the content
    const padding = 50;
    const contentWidth = bbox.width + padding * 2;
    const contentHeight = bbox.height + padding * 2;

    // Set the SVG dimensions to fit the content
    clonedSvg.setAttribute("width", `${contentWidth}`);
    clonedSvg.setAttribute("height", `${contentHeight}`);
    clonedSvg.setAttribute(
      "viewBox",
      `${bbox.x - padding} ${bbox.y - padding} ${contentWidth} ${contentHeight}`,
    );

    // Remove the zoom transform from the container - the viewBox now handles positioning
    containerGroup.removeAttribute("transform");

    // Add white background for better visibility
    const bgRect = document.createElementNS(
      "http://www.w3.org/2000/svg",
      "rect",
    );
    bgRect.setAttribute("x", `${bbox.x - padding}`);
    bgRect.setAttribute("y", `${bbox.y - padding}`);
    bgRect.setAttribute("width", `${contentWidth}`);
    bgRect.setAttribute("height", `${contentHeight}`);
    bgRect.setAttribute("fill", "#1c1917"); // Dark background matching the app
    clonedSvg.insertBefore(bgRect, clonedSvg.firstChild);

    const svgData = new XMLSerializer().serializeToString(clonedSvg);
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
