import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

vi.mock("./app-sidebar-content", () => ({
  AppSidebarContent: ({
    onSelect,
  }: {
    onSelect?: () => HTMLElement | null;
  }) => (
    <button type="button" onClick={onSelect}>
      Alerts
    </button>
  ),
}));

import { MobileAppSidebar } from "./mobile-app-sidebar";

describe("MobileAppSidebar", () => {
  it("replaces the open hamburger with a viewport X while the overlay is visible", async () => {
    // Given
    const user = userEvent.setup();
    render(<MobileAppSidebar />);

    // When
    const openButton = screen.getByRole("button", { name: "Open menu" });
    await user.click(openButton);

    // Then
    expect(screen.getByRole("dialog", { name: "App sidebar" })).toBeVisible();
    const closeButton = screen.getByRole("button", { name: "Close menu" });
    expect(closeButton).toBeVisible();
    expect(closeButton.querySelector(".lucide-x")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Close" }),
    ).not.toBeInTheDocument();

    // When
    await user.click(closeButton);

    // Then
    expect(
      screen.queryByRole("dialog", { name: "App sidebar" }),
    ).not.toBeInTheDocument();
    expect(openButton).toHaveFocus();
  });

  it("closes after selecting an item from the shared sidebar content", async () => {
    // Given
    const user = userEvent.setup();
    render(<MobileAppSidebar />);
    await user.click(screen.getByRole("button", { name: "Open menu" }));

    // When
    await user.click(screen.getByRole("button", { name: "Alerts" }));

    // Then
    expect(
      screen.queryByRole("dialog", { name: "App sidebar" }),
    ).not.toBeInTheDocument();
  });
});
