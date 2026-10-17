import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { BreadcrumbNavigation } from "./breadcrumb-navigation";

const navigationMock = vi.hoisted(() => ({
  pathname: "/findings",
}));

vi.mock("next/navigation", () => ({
  usePathname: () => navigationMock.pathname,
  useSearchParams: () => new URLSearchParams(),
}));

describe("BreadcrumbNavigation", () => {
  afterEach(() => {
    navigationMock.pathname = "/findings";
  });

  it("renders the title action next to the current breadcrumb title", () => {
    // Given / When
    render(
      <BreadcrumbNavigation
        mode="auto"
        title="Findings"
        titleAction={<button type="button">Start product tour</button>}
      />,
    );

    // Then
    expect(
      screen.getByRole("heading", { name: "Findings" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Start product tour" }),
    ).toBeInTheDocument();
  });

  it("renders the page icon next to a top-level title", () => {
    // Given / When
    render(
      <BreadcrumbNavigation
        mode="auto"
        title="Findings"
        icon={<svg data-testid="page-icon" />}
      />,
    );

    // Then
    expect(screen.getByTestId("page-icon")).toBeInTheDocument();
  });

  it("shows the bundled section icon only on the first breadcrumb", () => {
    // Given
    navigationMock.pathname = "/scans/config";

    // When
    const { container } = render(
      <BreadcrumbNavigation
        mode="auto"
        title="Configuration"
        icon={<svg data-testid="page-icon" />}
      />,
    );

    // Then
    expect(container.querySelector("svg.lucide-timer")).toBeInTheDocument();
    expect(screen.queryByTestId("page-icon")).not.toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Configuration" }),
    ).toBeInTheDocument();
  });
});
