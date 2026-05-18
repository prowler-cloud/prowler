import type { Rect } from "@xyflow/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { AttackPathGraphData } from "@/types/attack-paths";

import { exportGraphAsJSON, exportGraphAsPNG } from "./export";

const bounds: Rect = { x: 0, y: 0, width: 100, height: 100 };

const graphData: AttackPathGraphData = {
  nodes: [
    { id: "internet", labels: ["Internet"], properties: { name: "Internet" } },
    {
      id: "ec2-1",
      labels: ["EC2Instance"],
      properties: { name: "api-server-01" },
    },
  ],
  edges: [
    { id: "edge-1", source: "internet", target: "ec2-1", type: "CAN_REACH" },
  ],
};

const buildContainerWithViewport = () => {
  const container = document.createElement("div");
  const reactFlow = document.createElement("div");
  reactFlow.className = "react-flow";
  const viewport = document.createElement("div");
  viewport.className = "react-flow__viewport";
  reactFlow.appendChild(viewport);
  container.appendChild(reactFlow);
  return container;
};

class TestImage {
  onload: (() => void) | null = null;
  onerror: (() => void) | null = null;
  decoding = "async";

  set src(_value: string) {
    queueMicrotask(() => this.onload?.());
  }
}

describe("exportGraphAsPNG", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.stubGlobal("Image", TestImage);
    vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:graph-export");
    vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
    vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockReturnValue({
      arc: vi.fn(),
      beginPath: vi.fn(),
      bezierCurveTo: vi.fn(),
      closePath: vi.fn(),
      fill: vi.fn(),
      fillRect: vi.fn(),
      fillText: vi.fn(),
      lineTo: vi.fn(),
      moveTo: vi.fn(),
      quadraticCurveTo: vi.fn(),
      restore: vi.fn(),
      save: vi.fn(),
      setLineDash: vi.fn(),
      stroke: vi.fn(),
    } as unknown as CanvasRenderingContext2D);
    vi.spyOn(HTMLCanvasElement.prototype, "toDataURL").mockReturnValue(
      "data:image/png;base64,AAAA",
    );
  });

  it("throws when the container is not mounted", async () => {
    await expect(
      exportGraphAsPNG(null, bounds, undefined, graphData),
    ).rejects.toThrow("Graph container not mounted");
  });

  it("throws when the React Flow root is missing inside the container", async () => {
    const container = document.createElement("div");

    await expect(
      exportGraphAsPNG(container, bounds, undefined, graphData),
    ).rejects.toThrow("React Flow root not found in container");
  });

  it("throws when the React Flow viewport is missing inside the container", async () => {
    const container = document.createElement("div");
    const reactFlow = document.createElement("div");
    reactFlow.className = "react-flow";
    container.appendChild(reactFlow);

    await expect(
      exportGraphAsPNG(container, bounds, undefined, graphData),
    ).rejects.toThrow("React Flow viewport not found in container");
  });

  it("throws when bounds are null (no nodes to export)", async () => {
    const container = buildContainerWithViewport();

    await expect(
      exportGraphAsPNG(container, null, undefined, graphData),
    ).rejects.toThrow("No nodes to export");
  });

  it("throws when graph data has no nodes", async () => {
    const container = buildContainerWithViewport();

    await expect(
      exportGraphAsPNG(container, bounds, undefined, { nodes: [] }),
    ).rejects.toThrow("No nodes to export");
  });

  it("renders graph data to a PNG download", async () => {
    const container = buildContainerWithViewport();
    const appendChild = vi.spyOn(document.body, "appendChild");

    await exportGraphAsPNG(container, bounds, "graph.png", graphData);

    expect(HTMLCanvasElement.prototype.toDataURL).toHaveBeenCalledWith(
      "image/png",
    );
    const link = appendChild.mock.calls.find(
      ([element]) => element instanceof HTMLAnchorElement,
    )?.[0] as HTMLAnchorElement | undefined;
    expect(link?.download).toBe("graph.png");
    expect(link?.href).toBe("data:image/png;base64,AAAA");
  });

  it("renders exported long resource labels with the same wrapping as graph nodes", async () => {
    const container = buildContainerWithViewport();
    const longLabelGraphData: AttackPathGraphData = {
      nodes: [
        {
          id: "role-1",
          labels: ["AWSRole"],
          properties: { name: "AWSReservedSSO_AdministratorAccessExtra" },
        },
      ],
    };

    await exportGraphAsPNG(container, bounds, "graph.png", longLabelGraphData);

    const context = vi.mocked(HTMLCanvasElement.prototype.getContext).mock
      .results[0]?.value as CanvasRenderingContext2D;
    const fillText = vi.mocked(context.fillText);

    expect(fillText).toHaveBeenCalledWith(
      "AWSReservedSSO_A",
      expect.any(Number),
      expect.any(Number),
      136,
    );
    expect(fillText).toHaveBeenCalledWith(
      "dministratorAcce",
      expect.any(Number),
      expect.any(Number),
      136,
    );
    expect(fillText).toHaveBeenCalledWith(
      "ssExtra",
      expect.any(Number),
      expect.any(Number),
      136,
    );
    expect(fillText).toHaveBeenCalledWith(
      "AWS Role",
      expect.any(Number),
      expect.any(Number),
      136,
    );
  });

  it("re-throws a generic export error when canvas is unavailable", async () => {
    const container = buildContainerWithViewport();
    vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockReturnValue(null);
    const consoleError = vi
      .spyOn(console, "error")
      .mockImplementation(() => {});

    await expect(
      exportGraphAsPNG(container, bounds, undefined, graphData),
    ).rejects.toThrow("Failed to export graph");
    expect(consoleError).toHaveBeenCalled();
  });
});

describe("exportGraphAsJSON", () => {
  it("re-throws a generic export error when serialization fails", () => {
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    const consoleError = vi
      .spyOn(console, "error")
      .mockImplementation(() => {});

    expect(() => exportGraphAsJSON(circular)).toThrow("Failed to export graph");
    expect(consoleError).toHaveBeenCalled();

    consoleError.mockRestore();
  });
});
