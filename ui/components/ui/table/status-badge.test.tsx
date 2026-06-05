import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { type Status, StatusBadge } from "./status-badge";

const cases: Array<{ status: Status; label: string; variant: string }> = [
  { status: "available", label: "Queued", variant: "tag" },
  { status: "queued", label: "Queued", variant: "tag" },
  { status: "scheduled", label: "scheduled", variant: "warning" },
  { status: "completed", label: "completed", variant: "success" },
  { status: "failed", label: "failed", variant: "error" },
  { status: "cancelled", label: "cancelled", variant: "error" },
];

describe("StatusBadge", () => {
  it.each(cases)(
    "renders $status as $label with $variant variant",
    ({ status, label }) => {
      render(<StatusBadge status={status} />);
      expect(screen.getByText(label)).toBeInTheDocument();
    },
  );

  it("renders the executing state with spinner and progress percentage", () => {
    const { container } = render(
      <StatusBadge status="executing" loadingProgress={42} />,
    );
    expect(screen.getByText("executing")).toBeInTheDocument();
    expect(screen.getByText("42%")).toBeInTheDocument();
    expect(container.querySelector("svg")).toHaveClass(
      "animate-spin",
      "motion-reduce:animate-none",
    );
  });

  it("animates status color changes without layout motion", () => {
    const { container } = render(<StatusBadge status="completed" />);
    const badge = container.querySelector("[data-slot='badge']");
    expect(badge).toHaveClass(
      "transition-[background-color,border-color,color,box-shadow]",
      "duration-200",
      "ease-out",
      "motion-reduce:transition-none",
    );
  });

  it("omits progress when loadingProgress is not provided", () => {
    render(<StatusBadge status="executing" />);
    expect(screen.getByText("executing")).toBeInTheDocument();
    expect(screen.queryByText("%", { exact: false })).toBeNull();
  });

  it("merges custom className", () => {
    const { container } = render(
      <StatusBadge status="completed" className="extra-class" />,
    );
    const badge = container.querySelector("[data-slot='badge']");
    expect(badge?.className).toContain("extra-class");
  });

  it("applies md size classes when size='md'", () => {
    const { container } = render(<StatusBadge status="completed" size="md" />);
    const badge = container.querySelector("[data-slot='badge']");
    expect(badge?.className).toContain("py-1");
  });
});
