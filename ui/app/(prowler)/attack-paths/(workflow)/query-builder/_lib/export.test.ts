import type { Rect } from "@xyflow/react";
import { domToPng } from "modern-screenshot";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { exportGraphAsJSON, exportGraphAsPNG } from "./export";

vi.mock("modern-screenshot", () => ({
  domToPng: vi.fn(),
}));

const bounds: Rect = { x: 0, y: 0, width: 100, height: 100 };

const buildContainerWithViewport = () => {
  const container = document.createElement("div");
  const viewport = document.createElement("div");
  viewport.className = "react-flow__viewport";
  container.appendChild(viewport);
  return container;
};

describe("exportGraphAsPNG", () => {
  beforeEach(() => {
    vi.mocked(domToPng).mockReset();
  });

  it("throws when the container is not mounted", async () => {
    await expect(exportGraphAsPNG(null, bounds)).rejects.toThrow(
      "Graph container not mounted",
    );
    expect(domToPng).not.toHaveBeenCalled();
  });

  it("throws when the React Flow viewport is missing inside the container", async () => {
    const container = document.createElement("div");

    await expect(exportGraphAsPNG(container, bounds)).rejects.toThrow(
      "React Flow viewport not found in container",
    );
    expect(domToPng).not.toHaveBeenCalled();
  });

  it("throws when bounds are null (no nodes to export)", async () => {
    const container = buildContainerWithViewport();

    await expect(exportGraphAsPNG(container, null)).rejects.toThrow(
      "No nodes to export",
    );
    expect(domToPng).not.toHaveBeenCalled();
  });

  it("re-throws a generic export error when domToPng rejects", async () => {
    const container = buildContainerWithViewport();
    vi.mocked(domToPng).mockRejectedValueOnce(new Error("rasterizer boom"));
    const consoleError = vi
      .spyOn(console, "error")
      .mockImplementation(() => {});

    await expect(exportGraphAsPNG(container, bounds)).rejects.toThrow(
      "Failed to export graph",
    );
    expect(domToPng).toHaveBeenCalledOnce();
    expect(consoleError).toHaveBeenCalled();

    consoleError.mockRestore();
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
