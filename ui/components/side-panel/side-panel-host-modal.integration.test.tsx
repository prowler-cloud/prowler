import { useState } from "react";
import { beforeEach, describe, expect, it } from "vitest";
import { page, userEvent } from "vitest/browser";

import { render } from "@/__tests__/render-browser";
import { SidePanel } from "@/components/shadcn/side-panel/side-panel";
import { SIDE_PANEL_ELEMENT_ID } from "@/lib/ui-layout";
import {
  selectHasModalHost,
  SIDE_PANEL_TAB,
  useSidePanelStore,
} from "@/store/side-panel";

import { SidePanelHostModal } from "./side-panel-host-modal";

const PANEL_WIDTH = 480;

function PanelStandIn() {
  const isOpen = useSidePanelStore((state) => state.isOpen);
  return (
    <SidePanel
      id={SIDE_PANEL_ELEMENT_ID}
      open={isOpen}
      aria-label="Side panel"
      style={{ width: PANEL_WIDTH }}
    >
      <textarea aria-label="Lighthouse composer" />
    </SidePanel>
  );
}

function WizardStandIn() {
  return (
    <>
      <PanelStandIn />
      <SidePanelHostModal
        open
        onOpenChange={() => {}}
        title="Adding A Provider"
      >
        <input aria-label="AWS account ID" />
      </SidePanelHostModal>
    </>
  );
}

// The page behind goes inert while the wizard is open, like MainLayout does.
function ShellWithOpener() {
  const isShellInert = useSidePanelStore(selectHasModalHost);
  const [open, setOpen] = useState(false);
  return (
    <>
      <main inert={isShellInert}>
        <button type="button" onClick={() => setOpen(true)}>
          Add provider
        </button>
      </main>
      <PanelStandIn />
      <SidePanelHostModal
        open={open}
        onOpenChange={setOpen}
        title="Adding A Provider"
      >
        <input aria-label="AWS account ID" />
      </SidePanelHostModal>
    </>
  );
}

describe("SidePanelHostModal beside the side panel", () => {
  beforeEach(() => {
    useSidePanelStore.setState({
      isOpen: false,
      selectedTab: SIDE_PANEL_TAB.AI_CHAT,
      width: PANEL_WIDTH,
      modalHostCount: 0,
    });
  });

  it("lets the user chat in the panel without losing the wizard or its input", async () => {
    // Given: the user is halfway through the wizard
    render(<WizardStandIn />);
    await userEvent.fill(page.getByLabelText("AWS account ID"), "123456789012");

    // When: Lighthouse opens beside it and the user writes in the composer
    useSidePanelStore.getState().openPanel(SIDE_PANEL_TAB.AI_CHAT);
    await userEvent.click(page.getByLabelText("Lighthouse composer"));
    await userEvent.keyboard("How do I create the IAM role?");

    // Then: the wizard is still there, untouched, and clear of the panel
    await expect.element(page.getByRole("dialog")).toBeVisible();
    await expect
      .element(page.getByLabelText("AWS account ID"))
      .toHaveValue("123456789012");
    await expect
      .element(page.getByLabelText("Lighthouse composer"))
      .toHaveValue("How do I create the IAM role?");
    await expect
      .poll(
        () => page.getByRole("dialog").element().getBoundingClientRect().right,
      )
      .toBeLessThanOrEqual(window.innerWidth - PANEL_WIDTH);
  });

  it("closes only the panel on Escape inside it and hands focus back to the wizard", async () => {
    // Given
    render(<WizardStandIn />);
    useSidePanelStore.getState().openPanel(SIDE_PANEL_TAB.AI_CHAT);
    await userEvent.click(page.getByLabelText("Lighthouse composer"));

    // When
    await userEvent.keyboard("{Escape}");

    // Then
    expect(useSidePanelStore.getState().isOpen).toBe(false);
    await expect.element(page.getByRole("dialog")).toBeVisible();
    await expect.element(page.getByRole("dialog")).toHaveFocus();
  });

  it("gives focus back to the button that opened the wizard once the page is usable again", async () => {
    // Given: the user opened the wizard and is typing in it
    render(<ShellWithOpener />);
    await userEvent.click(page.getByRole("button", { name: "Add provider" }));
    await userEvent.click(page.getByLabelText("AWS account ID"));
    await userEvent.keyboard("1234");

    // When
    await userEvent.keyboard("{Escape}");

    // Then
    await expect.element(page.getByRole("dialog")).not.toBeInTheDocument();
    await expect
      .element(page.getByRole("button", { name: "Add provider" }))
      .toHaveFocus();
  });
});
