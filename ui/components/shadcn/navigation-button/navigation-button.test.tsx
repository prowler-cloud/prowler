import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { NavigationButton } from "./navigation-button";

describe("NavigationButton", () => {
  it("composes an active navigation link without rendering a nested button", () => {
    // Given / When
    render(
      <NavigationButton asChild active>
        <a href="/findings">Findings</a>
      </NavigationButton>,
    );

    // Then
    const link = screen.getByRole("link", { name: "Findings" });
    expect(link).toHaveAttribute("data-slot", "navigation-button");
    expect(link).toHaveAttribute("data-active", "true");
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it("defaults native navigation controls to non-submitting buttons", () => {
    // Given / When
    render(<NavigationButton variant="toggle">Chat</NavigationButton>);

    // Then
    const button = screen.getByRole("button", { name: "Chat" });
    expect(button).toHaveAttribute("type", "button");
    expect(button).toHaveAttribute("data-active", "false");
  });
});
