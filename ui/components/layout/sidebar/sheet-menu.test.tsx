import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/components/icons", () => ({
  ProwlerBrand: () => <span>Prowler</span>,
}));

vi.mock("@/components/layout/sidebar/menu", () => ({
  Menu: ({ onSelect }: { onSelect?: () => void }) => (
    <button type="button" onClick={onSelect}>
      Alerts
    </button>
  ),
}));

import { SheetMenu } from "./sheet-menu";

describe("SheetMenu", () => {
  it("should close after selecting a menu action", async () => {
    // Given
    const user = userEvent.setup();
    render(<SheetMenu />);

    // When
    await user.click(screen.getByRole("button", { name: "Open menu" }));
    expect(screen.getByRole("dialog", { name: "Sidebar" })).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Alerts" }));

    // Then
    expect(
      screen.queryByRole("dialog", { name: "Sidebar" }),
    ).not.toBeInTheDocument();
  });

  it("hides the mobile menu based on the viewport, not the narrowed content", () => {
    // Given / When
    render(<SheetMenu />);

    // Then
    expect(screen.getByRole("button", { name: "Open menu" })).toHaveClass(
      "min-[64rem]:hidden",
    );
  });
});
