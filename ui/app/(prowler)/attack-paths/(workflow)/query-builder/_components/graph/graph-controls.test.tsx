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
  });

  it("enables the export button and invokes the callback when onExport is provided", async () => {
    const user = userEvent.setup();
    const onExport = vi.fn();

    render(<GraphControls {...baseProps} onExport={onExport} />);

    const exportButton = screen.getByRole("button", {
      name: /^export graph$/i,
    });

    await user.click(exportButton);

    expect(onExport).toHaveBeenCalledTimes(1);
  });

  it("shows collapse all only when available and invokes its handler", async () => {
    // Given
    const user = userEvent.setup();
    const onCollapse = vi.fn();
    const { rerender } = render(
      <GraphControls {...baseProps} collapseAll={{ can: false, onCollapse }} />,
    );

    // Then
    expect(
      screen.queryByRole("button", { name: /collapse all groups/i }),
    ).not.toBeInTheDocument();

    // When
    rerender(
      <GraphControls {...baseProps} collapseAll={{ can: true, onCollapse }} />,
    );
    await user.click(
      screen.getByRole("button", { name: /collapse all groups/i }),
    );

    // Then
    expect(onCollapse).toHaveBeenCalledTimes(1);
  });
});
