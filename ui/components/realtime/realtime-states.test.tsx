import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { PanelFailure } from "./realtime-states";

describe("PanelFailure", () => {
  it("shows the real-time data store empty state for a 503, not an error", () => {
    render(
      <PanelFailure
        failure={{ ok: false, status: 503, error: "x" }}
        onRetry={vi.fn()}
      />,
    );

    expect(
      screen.getByText("Real-time data store not configured"),
    ).toBeVisible();
    expect(screen.getByText(/ClickHouse/)).toBeVisible();
  });

  it("explains a missing permission on a 403", () => {
    render(<PanelFailure failure={{ ok: false, status: 403, error: "x" }} />);

    expect(screen.getByText("You do not have access to this")).toBeVisible();
  });

  it("offers a retry for a generic error and none for a 404", async () => {
    const user = userEvent.setup();
    const onRetry = vi.fn();
    const { rerender } = render(
      <PanelFailure
        failure={{ ok: false, status: 500, error: "Boom" }}
        onRetry={onRetry}
        subject="the overview"
      />,
    );

    expect(screen.getByText("Could not load the overview")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Retry" }));
    expect(onRetry).toHaveBeenCalledTimes(1);

    rerender(
      <PanelFailure
        failure={{ ok: false, status: 404, error: "x" }}
        onRetry={onRetry}
      />,
    );
    expect(
      screen.queryByRole("button", { name: "Retry" }),
    ).not.toBeInTheDocument();
  });
});
