import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogTitle,
  DialogTrigger,
} from "./dialog";

function renderOpenDialog() {
  return render(
    <Dialog open>
      <DialogTrigger>Open modal</DialogTrigger>
      <DialogContent>
        <DialogTitle>Launch scan</DialogTitle>
        <DialogDescription>Configure scan settings</DialogDescription>
      </DialogContent>
    </Dialog>,
  );
}

describe("Dialog", () => {
  it("renders controlled content through the Radix Dialog API", () => {
    // Given
    renderOpenDialog();

    // When
    const dialog = screen.getByRole("dialog", { name: "Launch scan" });

    // Then
    expect(dialog).toBeVisible();
    expect(dialog).toHaveAttribute("data-slot", "dialog-content");
    expect(screen.getByText("Configure scan settings")).toBeVisible();
  });

  it("uses an intentional overlay motion contract", () => {
    // Given
    renderOpenDialog();

    // When
    const overlay = document.querySelector("[data-slot='dialog-overlay']");

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

  it("uses an intentional content motion contract", () => {
    // Given
    renderOpenDialog();

    // When
    const dialog = screen.getByRole("dialog", { name: "Launch scan" });

    // Then
    expect(dialog).toHaveClass(
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
      "motion-reduce:animate-none",
      "motion-reduce:transform-none",
      "motion-reduce:transition-none",
    );
  });
});
