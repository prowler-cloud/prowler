import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { LoadingState } from "./loading-state";

describe("LoadingState", () => {
  it("renders a spinner with the default size", () => {
    const { container } = render(<LoadingState />);
    const svg = container.querySelector("svg");
    expect(svg).toHaveAttribute("aria-label", "Loading");
    expect(
      svg?.className.baseVal ?? svg?.getAttribute("class") ?? "",
    ).toContain("size-6");
  });

  it("does not render a label when none is provided", () => {
    render(<LoadingState />);
    expect(screen.queryByText(/loading/i, { selector: "span" })).toBeNull();
  });

  it("renders the label when provided", () => {
    render(<LoadingState label="Loading findings..." />);
    expect(screen.getByText("Loading findings...")).toBeInTheDocument();
  });

  it("forwards spinnerClassName to the Spinner so callers can override the size", () => {
    const { container } = render(<LoadingState spinnerClassName="size-5" />);
    const svg = container.querySelector("svg");
    expect(svg?.getAttribute("class") ?? "").toContain("size-5");
  });

  it("forwards className to the wrapper element", () => {
    const { container } = render(<LoadingState className="custom-wrapper" />);
    expect(container.firstChild).toHaveClass("custom-wrapper");
  });

  it("animates the loading state entry and label color subtly", () => {
    const { container } = render(<LoadingState label="Loading findings..." />);
    expect(container.firstChild).toHaveClass(
      "animate-in",
      "fade-in-0",
      "duration-200",
      "ease-out",
      "motion-reduce:animate-none",
      "motion-reduce:transition-none",
    );
    expect(screen.getByText("Loading findings...")).toHaveClass(
      "transition-colors",
      "duration-200",
      "ease-out",
      "motion-reduce:transition-none",
    );
  });
});
