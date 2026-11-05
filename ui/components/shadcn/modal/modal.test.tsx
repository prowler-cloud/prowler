import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";

import { Modal } from "./modal";

interface OpenerHarnessProps {
  isNonModal: boolean;
  onCloseAutoFocus?: (event: Event) => void;
  // A field that takes focus as it mounts, so Radix skips its open autofocus.
  hasAutoFocusField?: boolean;
}

// A controlled Modal opened by a plain button, the way the app opens them.
function OpenerHarness({
  isNonModal,
  onCloseAutoFocus,
  hasAutoFocusField = false,
}: OpenerHarnessProps) {
  const [open, setOpen] = useState(false);
  const body = <input aria-label="Account ID" autoFocus={hasAutoFocusField} />;
  return (
    <>
      <button type="button" onClick={() => setOpen(true)}>
        Add provider
      </button>
      <button type="button">Elsewhere</button>
      {isNonModal ? (
        <Modal
          open={open}
          onOpenChange={setOpen}
          onCloseAutoFocus={onCloseAutoFocus}
          modal={false}
          title="Wizard"
        >
          {body}
        </Modal>
      ) : (
        <Modal
          open={open}
          onOpenChange={setOpen}
          onCloseAutoFocus={onCloseAutoFocus}
          title="Wizard"
        >
          {body}
        </Modal>
      )}
    </>
  );
}

describe("Modal focus on close", () => {
  it.each([
    { mode: "modal", isNonModal: false, closeWith: "the close button" },
    { mode: "modal", isNonModal: false, closeWith: "Escape" },
    { mode: "non-modal", isNonModal: true, closeWith: "the close button" },
    { mode: "non-modal", isNonModal: true, closeWith: "Escape" },
  ])(
    "returns focus to the button that opened the $mode dialog after closing with $closeWith",
    async ({ isNonModal, closeWith }) => {
      // Given
      const user = userEvent.setup();
      render(<OpenerHarness isNonModal={isNonModal} />);
      await user.click(screen.getByRole("button", { name: "Add provider" }));
      await user.click(await screen.findByLabelText("Account ID"));

      // When
      if (closeWith === "Escape") {
        await user.keyboard("{Escape}");
      } else {
        await user.click(screen.getByRole("button", { name: "Close" }));
      }

      // Then
      await waitFor(() =>
        expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
      );
      await waitFor(() =>
        expect(
          screen.getByRole("button", { name: "Add provider" }),
        ).toHaveFocus(),
      );
    },
  );

  it.each([
    { mode: "modal", isNonModal: false },
    { mode: "non-modal", isNonModal: true },
  ])(
    "returns focus to the opener of a $mode dialog whose field takes focus on mount",
    async ({ isNonModal }) => {
      // Given
      const user = userEvent.setup();
      render(<OpenerHarness isNonModal={isNonModal} hasAutoFocusField />);
      await user.click(screen.getByRole("button", { name: "Add provider" }));
      await waitFor(() =>
        expect(screen.getByLabelText("Account ID")).toHaveFocus(),
      );

      // When
      await user.click(screen.getByRole("button", { name: "Close" }));

      // Then
      await waitFor(() =>
        expect(
          screen.getByRole("button", { name: "Add provider" }),
        ).toHaveFocus(),
      );
    },
  );

  it("keeps the focus target chosen by the consumer", async () => {
    // Given: the consumer sends focus somewhere else on close
    const user = userEvent.setup();
    render(
      <OpenerHarness
        isNonModal={false}
        onCloseAutoFocus={(event) => {
          event.preventDefault();
          screen.getByRole("button", { name: "Elsewhere" }).focus();
        }}
      />,
    );
    await user.click(screen.getByRole("button", { name: "Add provider" }));
    await user.click(await screen.findByLabelText("Account ID"));

    // When
    await user.click(screen.getByRole("button", { name: "Close" }));

    // Then
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Elsewhere" })).toHaveFocus(),
    );
  });
});

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
