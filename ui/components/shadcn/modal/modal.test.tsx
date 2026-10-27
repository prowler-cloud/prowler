import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { Modal } from "./modal";

function getBackdrop(): HTMLElement {
  const backdrop = document.querySelector<HTMLElement>(
    '[data-slot="modal-backdrop"]',
  );
  if (!backdrop) throw new Error("Modal backdrop not rendered");
  return backdrop;
}

describe("Modal (non-modal)", () => {
  it("stays open while the user works outside it", async () => {
    // Given
    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    render(
      <>
        <input aria-label="Side panel composer" />
        <Modal open onOpenChange={onOpenChange} modal={false} title="Wizard">
          <p>Wizard body</p>
        </Modal>
      </>,
    );
    await screen.findByText("Wizard body");

    // When: the user clicks and types in a control outside the dialog
    await user.click(screen.getByLabelText("Side panel composer"));
    await user.keyboard("help");

    // Then
    expect(onOpenChange).not.toHaveBeenCalled();
    expect(screen.getByLabelText("Side panel composer")).toHaveValue("help");
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("closes when the backdrop is clicked", async () => {
    // Given
    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    render(
      <Modal open onOpenChange={onOpenChange} modal={false} title="Wizard">
        <p>Wizard body</p>
      </Modal>,
    );
    await screen.findByText("Wizard body");

    // When
    await user.click(getBackdrop());

    // Then
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it("leaves the reserved right inset uncovered", async () => {
    // Given / When
    render(
      <Modal
        open
        onOpenChange={vi.fn()}
        modal={false}
        insetRight={480}
        title="Wizard"
      >
        <p>Wizard body</p>
      </Modal>,
    );
    await screen.findByText("Wizard body");

    // Then: the frame holding backdrop and dialog stops where the inset starts
    const frame = document.querySelector('[data-slot="modal-frame"]');
    expect(frame).toContainElement(getBackdrop());
    expect(frame).toContainElement(screen.getByRole("dialog"));
    expect(frame).toHaveStyle({ right: "480px" });
  });
});
