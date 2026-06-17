import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { BreadcrumbNavigation } from "./breadcrumb-navigation";

vi.mock("next/navigation", () => ({
  usePathname: () => "/findings",
  useSearchParams: () => new URLSearchParams(),
}));

vi.mock("@iconify/react", () => ({
  Icon: ({ icon }: { icon: string }) => <span aria-label={icon} />,
}));

describe("BreadcrumbNavigation", () => {
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
});
