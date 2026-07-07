import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { SIDE_PANEL_TAB, useSidePanelStore } from "@/store/side-panel";

import { DetailSidePanel } from "./detail-side-panel";
import { GlobalSidePanel } from "./global-side-panel";

const { isCloudMock } = vi.hoisted(() => ({ isCloudMock: vi.fn(() => true) }));

vi.mock("@/lib/shared/env", () => ({ isCloud: isCloudMock }));

vi.mock("next/navigation", () => ({
  usePathname: () => "/findings",
}));

vi.mock(
  "@/app/(prowler)/lighthouse/_components/panel/lighthouse-panel-chat",
  () => ({
    LighthousePanelChat: () => (
      <div data-testid="panel-chat-content">chat content</div>
    ),
  }),
);

// Mimics a table host: local open state, detail content as children.
function Host({ initialOpen = true }: { initialOpen?: boolean }) {
  const [open, setOpen] = useState(initialOpen);
  return (
    <>
      <button type="button" onClick={() => setOpen(true)}>
        Open detail
      </button>
      <GlobalSidePanel />
      <DetailSidePanel
        open={open}
        onOpenChange={setOpen}
        title="Resource Details"
        description="View the resource details"
      >
        <div data-testid="detail-content">detail body</div>
      </DetailSidePanel>
      <output data-testid="host-open-state">{String(open)}</output>
    </>
  );
}

describe("DetailSidePanel", () => {
  beforeEach(() => {
    isCloudMock.mockReturnValue(true);
    localStorage.clear();
    useSidePanelStore.setState({
      isOpen: false,
      selectedTab: SIDE_PANEL_TAB.AI_CHAT,
      hasBeenOpened: false,
      contextTab: null,
      contextOutlet: null,
    });
  });

  it("portals the detail content into the global panel when open", async () => {
    // Given / When
    render(<Host />);

    // Then: the content renders inside the panel's context outlet
    const detail = await screen.findByTestId("detail-content");
    expect(
      screen.getByTestId("side-panel-context-outlet").contains(detail),
    ).toBe(true);
    expect(screen.getByRole("tab", { name: "Details" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    expect(useSidePanelStore.getState().isOpen).toBe(true);
  });

  it("clears the host selection when the panel is dismissed", async () => {
    // Given
    const user = userEvent.setup();
    render(<Host />);
    await screen.findByTestId("detail-content");

    // When
    await user.click(screen.getByRole("button", { name: "Close side panel" }));

    // Then: the host's open state flips, the content unmounts, the tab is gone
    expect(screen.getByTestId("host-open-state")).toHaveTextContent("false");
    expect(screen.queryByTestId("detail-content")).not.toBeInTheDocument();
    expect(useSidePanelStore.getState().contextTab).toBeNull();
  });

  it("keeps the detail mounted while chatting on the AI tab", async () => {
    // Given
    const user = userEvent.setup();
    render(<Host />);
    await screen.findByTestId("detail-content");

    // When
    await user.click(screen.getByRole("tab", { name: "Lighthouse AI" }));

    // Then: chat is up, detail DOM survives hidden (carousel/scroll intact)
    expect(await screen.findByTestId("panel-chat-content")).toBeInTheDocument();
    expect(screen.getByTestId("detail-content")).toBeInTheDocument();
    expect(screen.getByTestId("detail-content")).not.toBeVisible();
  });

  it("registers nothing while closed and registers on open", async () => {
    // Given
    const user = userEvent.setup();
    render(<Host initialOpen={false} />);
    expect(useSidePanelStore.getState().contextTab).toBeNull();

    // When
    await user.click(screen.getByRole("button", { name: "Open detail" }));

    // Then
    expect(await screen.findByTestId("detail-content")).toBeInTheDocument();
    expect(useSidePanelStore.getState().contextTab?.label).toBe("Details");
  });
});
