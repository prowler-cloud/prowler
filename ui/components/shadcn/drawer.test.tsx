import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import {
  Drawer,
  DrawerContent,
  DrawerDescription,
  DrawerTitle,
  DrawerTrigger,
} from "./drawer";

function renderOpenDrawer() {
  return render(
    <Drawer open>
      <DrawerTrigger>Open drawer</DrawerTrigger>
      <DrawerContent>
        <DrawerTitle>Resource details</DrawerTitle>
        <DrawerDescription>Review resource metadata</DrawerDescription>
      </DrawerContent>
    </Drawer>,
  );
}

describe("Drawer", () => {
  it("renders controlled content through the Vaul Drawer API", () => {
    // Given
    renderOpenDrawer();

    // When
    const drawer = screen.getByRole("dialog", { name: "Resource details" });

    // Then
    expect(drawer).toBeVisible();
    expect(drawer).toHaveAttribute("data-slot", "drawer-content");
    expect(screen.getByText("Review resource metadata")).toBeVisible();
  });

  it("uses an intentional overlay motion contract", () => {
    // Given
    renderOpenDrawer();

    // When
    const overlay = document.querySelector("[data-slot='drawer-overlay']");

    // Then
    expect(overlay).toHaveClass(
      "duration-200",
      "ease-out",
      "data-[state=open]:animate-in",
      "data-[state=open]:fade-in-0",
      "data-[state=closed]:animate-out",
      "data-[state=closed]:fade-out-0",
      "data-[state=closed]:duration-100",
      "data-[state=closed]:ease-in",
      "motion-reduce:animate-none",
      "motion-reduce:transition-none",
    );
  });

  it("uses direction-aware drawer content motion", () => {
    // Given
    renderOpenDrawer();

    // When
    const drawer = screen.getByRole("dialog", { name: "Resource details" });

    // Then
    expect(drawer).toHaveClass(
      "duration-200",
      "ease-out",
      "data-[state=open]:animate-in",
      "data-[state=closed]:animate-out",
      "data-[state=closed]:duration-100",
      "data-[state=closed]:ease-in",
      "data-[vaul-drawer-direction=bottom]:slide-in-from-bottom-full",
      "data-[vaul-drawer-direction=bottom]:data-[state=closed]:slide-out-to-bottom-full",
      "data-[vaul-drawer-direction=top]:slide-in-from-top-full",
      "data-[vaul-drawer-direction=top]:data-[state=closed]:slide-out-to-top-full",
      "data-[vaul-drawer-direction=right]:slide-in-from-right-full",
      "data-[vaul-drawer-direction=right]:data-[state=closed]:slide-out-to-right-full",
      "data-[vaul-drawer-direction=left]:slide-in-from-left-full",
      "data-[vaul-drawer-direction=left]:data-[state=closed]:slide-out-to-left-full",
      "motion-reduce:animate-none",
      "motion-reduce:transform-none",
      "motion-reduce:transition-none",
    );
  });
});
