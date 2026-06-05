import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
} from "./dropdown";

function renderActionsDropdown() {
  return render(
    <DropdownMenu open>
      <DropdownMenuTrigger>Open actions</DropdownMenuTrigger>
      <DropdownMenuContent>
        <DropdownMenuItem>Edit</DropdownMenuItem>
        <DropdownMenuItem>Delete</DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>,
  );
}

describe("DropdownMenu", () => {
  it("renders open menu content through the Radix DropdownMenu API", () => {
    // Given
    renderActionsDropdown();

    // When
    const menu = screen.getByRole("menu");

    // Then
    expect(menu).toBeVisible();
    expect(menu).toHaveAttribute("data-slot", "dropdown-menu-content");
    expect(screen.getByRole("menuitem", { name: "Edit" })).toBeVisible();
    expect(screen.getByRole("menuitem", { name: "Delete" })).toBeVisible();
  });

  it("uses an intentional open and close motion contract", () => {
    // Given
    renderActionsDropdown();

    // When
    const menu = screen.getByRole("menu");

    // Then
    expect(menu).toHaveClass(
      "origin-(--radix-dropdown-menu-content-transform-origin)",
      "duration-200",
      "ease-out",
      "data-[state=open]:animate-in",
      "data-[state=open]:fade-in-0",
      "data-[state=open]:zoom-in-95",
      "data-[state=closed]:animate-out",
      "data-[state=closed]:fade-out-0",
      "data-[state=closed]:zoom-out-95",
      "data-[state=closed]:duration-100",
      "data-[state=closed]:ease-in",
    );
  });

  it("removes transform-heavy menu motion for reduced-motion users", () => {
    // Given
    renderActionsDropdown();

    // When
    const menu = screen.getByRole("menu");

    // Then
    expect(menu).toHaveClass(
      "motion-reduce:animate-none",
      "motion-reduce:transform-none",
      "motion-reduce:transition-none",
    );
  });

  it("applies the same motion contract to submenu content", () => {
    // Given
    render(
      <DropdownMenu open>
        <DropdownMenuTrigger>Open actions</DropdownMenuTrigger>
        <DropdownMenuContent>
          <DropdownMenuSub open>
            <DropdownMenuSubTrigger>More actions</DropdownMenuSubTrigger>
            <DropdownMenuSubContent>
              <DropdownMenuItem>Archive</DropdownMenuItem>
            </DropdownMenuSubContent>
          </DropdownMenuSub>
        </DropdownMenuContent>
      </DropdownMenu>,
    );

    // When
    const submenuContent = screen
      .getByRole("menuitem", { name: "Archive" })
      .closest("[data-slot='dropdown-menu-sub-content']");

    // Then
    expect(submenuContent).toHaveClass(
      "origin-(--radix-dropdown-menu-content-transform-origin)",
      "duration-200",
      "ease-out",
      "data-[state=open]:animate-in",
      "data-[state=closed]:animate-out",
      "data-[state=closed]:duration-100",
      "data-[state=closed]:ease-in",
      "motion-reduce:animate-none",
      "motion-reduce:transform-none",
      "motion-reduce:transition-none",
    );
  });
});
