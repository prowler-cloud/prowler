import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { SheetMenu } from "./sheet-menu";

vi.mock("@/components/layout/sidebar/menu", () => ({
  Menu: () => <nav>Menu</nav>,
}));

describe("SheetMenu", () => {
  it("hides the mobile menu based on the viewport, not the narrowed content", () => {
    // Given / When
    render(<SheetMenu />);

    // Then
    expect(screen.getByRole("button")).toHaveClass("min-[64rem]:hidden");
  });
});
