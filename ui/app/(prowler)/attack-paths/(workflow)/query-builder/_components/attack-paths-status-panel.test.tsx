import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ATTACK_PATHS_VIEW_STATES } from "../_lib/get-attack-paths-view-state";
import { AttackPathsStatusPanel } from "./attack-paths-status-panel";

describe("AttackPathsStatusPanel", () => {
  it("renders the no-scans message with a link to Scan Jobs", () => {
    render(
      <AttackPathsStatusPanel state={ATTACK_PATHS_VIEW_STATES.NO_SCANS} />,
    );
    expect(screen.getByText(/no scans available/i)).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: /go to scan jobs/i }),
    ).toHaveAttribute("href", "/scans");
  });

  it("renders the scan-running message", () => {
    render(
      <AttackPathsStatusPanel state={ATTACK_PATHS_VIEW_STATES.SCAN_RUNNING} />,
    );
    expect(screen.getByText(/scan in progress/i)).toBeInTheDocument();
  });

  it("renders the graph-building message with progress", () => {
    render(
      <AttackPathsStatusPanel
        state={ATTACK_PATHS_VIEW_STATES.GRAPH_BUILDING}
        progress={45}
      />,
    );
    expect(
      screen.getByText(/preparing attack paths data/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/45%/)).toBeInTheDocument();
  });

  it("renders the no-graph-data message", () => {
    render(
      <AttackPathsStatusPanel state={ATTACK_PATHS_VIEW_STATES.NO_GRAPH_DATA} />,
    );
    expect(screen.getByText(/no attack paths data/i)).toBeInTheDocument();
  });

  it("renders the error message and calls onRetry when Retry is clicked", () => {
    const onRetry = vi.fn();
    render(
      <AttackPathsStatusPanel
        state={ATTACK_PATHS_VIEW_STATES.ERROR}
        onRetry={onRetry}
      />,
    );
    expect(screen.getByText(/couldn.t load scans/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /retry/i }));
    expect(onRetry).toHaveBeenCalledOnce();
  });

  it("renders nothing for the ready state", () => {
    const { container } = render(
      <AttackPathsStatusPanel state={ATTACK_PATHS_VIEW_STATES.READY} />,
    );
    expect(container).toBeEmptyDOMElement();
  });
});
