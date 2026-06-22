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
});
