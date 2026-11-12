import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { SIDE_PANEL_ELEMENT_ID } from "@/lib/ui-layout";
import { SIDE_PANEL_TAB, useSidePanelStore } from "@/store/side-panel";

import { SidePanelHostModal } from "./side-panel-host-modal";

vi.mock("next/navigation", () => ({
  usePathname: () => "/providers",
}));

function renderWithPanel(onOpenChange = vi.fn(), open = true) {
  return render(
    <>
      <aside id={SIDE_PANEL_ELEMENT_ID}>
        <textarea aria-label="Lighthouse composer" />
      </aside>
      <SidePanelHostModal
        open={open}
        onOpenChange={onOpenChange}
        title="Add provider"
      >
        <button type="button">Next</button>
      </SidePanelHostModal>
    </>,
  );
}

describe("SidePanelHostModal", () => {
  beforeEach(() => {
    useSidePanelStore.setState({
      isOpen: true,
      selectedTab: SIDE_PANEL_TAB.AI_CHAT,
      modalHostCount: 0,
    });
  });

  it("keeps the dialog open while the user chats in the side panel", async () => {
    // Given
    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    renderWithPanel(onOpenChange);
    await screen.findByRole("dialog");

    // When
    await user.click(screen.getByLabelText("Lighthouse composer"));
    await user.keyboard("How do I create the IAM role?");

    // Then
    expect(onOpenChange).not.toHaveBeenCalled();
    expect(screen.getByLabelText("Lighthouse composer")).toHaveValue(
      "How do I create the IAM role?",
    );
  });

  it("closes only the side panel when Escape is pressed inside it", async () => {
    // Given
    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    renderWithPanel(onOpenChange);
    await user.click(await screen.findByLabelText("Lighthouse composer"));

    // When
    await user.keyboard("{Escape}");

    // Then: the panel closes, the dialog stays and takes the focus back
    expect(useSidePanelStore.getState().isOpen).toBe(false);
    expect(onOpenChange).not.toHaveBeenCalled();
    expect(screen.getByRole("dialog")).toHaveFocus();
  });

  it("still closes on Escape pressed inside the dialog", async () => {
    // Given
    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    renderWithPanel(onOpenChange);
    await user.click(await screen.findByRole("button", { name: "Next" }));

    // When
    await user.keyboard("{Escape}");

    // Then
    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(useSidePanelStore.getState().isOpen).toBe(true);
  });

  it("holds the app shell inert only while it is open", async () => {
    // Given
    const { rerender } = renderWithPanel();
    await screen.findByRole("dialog");
    expect(useSidePanelStore.getState().modalHostCount).toBe(1);

    // When
    rerender(
      <SidePanelHostModal open={false} onOpenChange={vi.fn()} title="Add">
        <button type="button">Next</button>
      </SidePanelHostModal>,
    );

    // Then
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(useSidePanelStore.getState().modalHostCount).toBe(0);
  });
});
