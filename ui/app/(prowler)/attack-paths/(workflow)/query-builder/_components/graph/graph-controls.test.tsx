import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { GraphControls } from "./graph-controls";

const baseProps = {
  onZoomIn: vi.fn(),
  onZoomOut: vi.fn(),
  onFitToScreen: vi.fn(),
};

describe("GraphControls", () => {
  it("disables the export button and surfaces the unavailable message when no onExport is provided", () => {
    render(<GraphControls {...baseProps} />);

    const exportButton = screen.getByRole("button", {
      name: /export available soon/i,
    });

    expect(exportButton).toBeDisabled();
    expect(
      screen.queryByRole("button", { name: /^export graph$/i }),
    ).not.toBeInTheDocument();
  });

  it("enables the export button and invokes the callback when onExport is provided", async () => {
    const user = userEvent.setup();
    const onExport = vi.fn();

    render(<GraphControls {...baseProps} onExport={onExport} />);

    const exportButton = screen.getByRole("button", {
      name: /^export graph$/i,
    });

    expect(exportButton).toBeEnabled();

    await user.click(exportButton);

    expect(onExport).toHaveBeenCalledTimes(1);
  });

  it("uses the design-system icon size for every toolbar action", () => {
    render(
      <GraphControls
        {...baseProps}
        onExport={vi.fn()}
        collapseAll={{ can: true, onCollapse: vi.fn() }}
      />,
    );

    for (const name of [
      "Collapse all groups",
      "Zoom in",
      "Zoom out",
      "Fit graph to view",
      "Export graph",
    ]) {
      const button = screen.getByRole("button", { name });
      expect(button).toHaveClass("size-8");
      expect(button).not.toHaveClass("h-8");
      expect(button).not.toHaveClass("w-8");
      expect(button).not.toHaveClass("p-0");
    }
  });
});
