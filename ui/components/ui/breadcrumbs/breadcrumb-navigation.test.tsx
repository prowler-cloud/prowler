import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

const navigationState = vi.hoisted(() => ({
  pathname: "/alerts",
}));

vi.mock("next/navigation", () => ({
  usePathname: () => navigationState.pathname,
  useSearchParams: () => new URLSearchParams(),
}));

vi.mock("next/link", () => ({
  default: ({ children, href }: { children: ReactNode; href: string }) => (
    <a href={href}>{children}</a>
  ),
}));

vi.mock("@iconify/react", () => ({
  Icon: ({ icon }: { icon: string }) => (
    <span
      data-icon={icon}
      data-testid={icon === "lucide:bell-ring" ? "alerts-icon" : icon}
    />
  ),
}));

vi.mock("@heroui/breadcrumbs", () => ({
  Breadcrumbs: ({ children }: { children: ReactNode }) => <nav>{children}</nav>,
  BreadcrumbItem: ({ children }: { children: ReactNode }) => (
    <span>{children}</span>
  ),
}));

import { BreadcrumbNavigation } from "./breadcrumb-navigation";

describe("BreadcrumbNavigation", () => {
  it("should show Alerts as the current canonical route", () => {
    // Given
    navigationState.pathname = "/alerts";

    // When
    render(
      <BreadcrumbNavigation
        mode="auto"
        title="Alerts"
        icon="lucide:bell-ring"
      />,
    );

    // Then
    expect(
      screen.queryByRole("link", { name: /integrations/i }),
    ).not.toBeInTheDocument();
    expect(screen.getByText("Alerts")).toBeInTheDocument();
    expect(screen.getByTestId("alerts-icon")).toBeInTheDocument();
  });
});
