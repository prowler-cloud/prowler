import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { SubmenuItem } from "./submenu-item";

vi.mock("next/navigation", () => ({
  usePathname: () => "/",
}));

const TestIcon = ({ size = 16 }: { size?: number }) => (
  <svg aria-hidden="true" height={size} width={size} />
);

describe("SubmenuItem", () => {
  it("should show the cloud-only tooltip for disabled cloud menu items", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <SubmenuItem
        href="/alerts"
        label="Alerts"
        icon={TestIcon}
        disabled
        highlight
        cloudOnly
      />,
    );

    // When
    const button = screen.getByRole("button", { name: /alerts/i });
    expect(button).toHaveAttribute("aria-disabled", "true");
    expect(button).toHaveClass(
      "cursor-not-allowed",
      "text-text-neutral-tertiary",
    );
    await user.hover(button.parentElement as HTMLElement);

    // Then
    expect(screen.getByText("New")).toHaveClass("h-5", "text-[10px]");
    expect(screen.queryByText("Cloud")).not.toBeInTheDocument();
    expect(
      await screen.findAllByText("Available in Prowler Cloud"),
    ).not.toHaveLength(0);
  });
});
