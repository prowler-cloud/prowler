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

vi.mock("@iconify/react", () => ({
  Icon: ({ icon }: { icon: string }) => <span aria-label={icon} />,
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

  it("does not render icons for secondary breadcrumb items", () => {
    // Given
    navigationMock.pathname = "/scans/config";

    // When
    render(
      <BreadcrumbNavigation
        mode="auto"
        title="Configuration"
        icon="lucide:sliders"
      />,
    );

    // Then
    expect(screen.getByLabelText("lucide:timer")).toBeInTheDocument();
    expect(screen.queryByLabelText("lucide:sliders")).not.toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Configuration" }),
    ).toBeInTheDocument();
  });
});
