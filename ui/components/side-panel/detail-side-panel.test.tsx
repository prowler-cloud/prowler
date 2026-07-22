import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useLighthouseContextStore } from "@/store/lighthouse-context/store";
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
        context={{
          kind: "finding",
          id: "finding-1",
          source: "focused",
          scopeKey: "findings:/findings",
          label: "Focused finding",
          findingId: "finding-1",
        }}
      >
        <div data-testid="detail-content">detail body</div>
      </DetailSidePanel>
      <output data-testid="host-open-state">{String(open)}</output>
    </>
  );
}

// Mimics two findings-table rows, each mounting its own DetailSidePanel with
// per-row open state — the real layout on the findings page.
function DualHost() {
  const [openA, setOpenA] = useState(false);
  const [openB, setOpenB] = useState(false);
  return (
    <>
      <button type="button" onClick={() => setOpenA(true)}>
        Open A
      </button>
      <button type="button" onClick={() => setOpenB(true)}>
        Open B
      </button>
      <GlobalSidePanel />
      <DetailSidePanel
        open={openA}
        onOpenChange={setOpenA}
        title="Finding A"
        context={{
          kind: "finding",
          id: "finding-a",
          source: "focused",
          scopeKey: "findings:/findings",
          label: "Focused finding A",
          findingId: "finding-a",
        }}
      >
        <div data-testid="detail-a">A body</div>
      </DetailSidePanel>
      <DetailSidePanel
        open={openB}
        onOpenChange={setOpenB}
        title="Finding B"
        context={{
          kind: "finding",
          id: "finding-b",
          source: "focused",
          scopeKey: "findings:/findings",
          label: "Focused finding B",
          findingId: "finding-b",
        }}
      >
        <div data-testid="detail-b">B body</div>
      </DetailSidePanel>
      <output data-testid="open-a">{String(openA)}</output>
      <output data-testid="open-b">{String(openB)}</output>
    </>
  );
}

function NavigatingHost() {
  const [findingId, setFindingId] = useState("finding-1");

  return (
    <>
      <button type="button" onClick={() => setFindingId("finding-2")}>
        Next finding
      </button>
      <GlobalSidePanel />
      <DetailSidePanel
        open
        onOpenChange={vi.fn()}
        title="Finding"
        context={{
          kind: "finding",
          id: findingId,
          source: "focused",
          scopeKey: "findings:/findings",
          label: "Focused finding",
          findingId,
        }}
      >
        <div data-testid="navigating-detail">{findingId}</div>
      </DetailSidePanel>
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
      contextOwnerToken: 0,
      contextOutlet: null,
    });
    useLighthouseContextStore.getState().resetContributions();
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
    expect(useLighthouseContextStore.getState().focused?.id).toBe("finding-1");

    // When
    await user.click(screen.getByRole("button", { name: "Close side panel" }));

    // Then
    expect(useLighthouseContextStore.getState().focused).toBeNull();
  });

  it("hands the panel to the newest detail view and closes the previous one", async () => {
    // Given: finding A's detail view owns the panel
    const user = userEvent.setup();
    render(<DualHost />);
    await user.click(screen.getByRole("button", { name: "Open A" }));
    await screen.findByTestId("detail-a");

    // When: the user opens finding B while A is still mounted
    await user.click(screen.getByRole("button", { name: "Open B" }));

    // Then: only B portals into the outlet; A closed itself
    const detailB = await screen.findByTestId("detail-b");
    expect(
      screen.getByTestId("side-panel-context-outlet").contains(detailB),
    ).toBe(true);
    expect(screen.queryByTestId("detail-a")).not.toBeInTheDocument();
    expect(screen.getByTestId("open-a")).toHaveTextContent("false");
    expect(screen.getByTestId("open-b")).toHaveTextContent("true");
    expect(useLighthouseContextStore.getState().focused?.id).toBe("finding-b");

    // When: the panel is dismissed
    await user.click(screen.getByRole("button", { name: "Close side panel" }));

    // Then: B (the current owner) is the one that clears its selection
    expect(screen.getByTestId("open-b")).toHaveTextContent("false");
    expect(screen.queryByTestId("detail-b")).not.toBeInTheDocument();
    expect(useSidePanelStore.getState().contextTab).toBeNull();
    expect(useLighthouseContextStore.getState().focused).toBeNull();
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

  it("updates focused context while navigating inside the current drawer", async () => {
    // Given
    const user = userEvent.setup();
    render(<NavigatingHost />);
    await screen.findByText("finding-1");
    expect(useLighthouseContextStore.getState().focused?.id).toBe("finding-1");

    // When
    await user.click(screen.getByRole("button", { name: "Next finding" }));

    // Then
    expect(screen.getByTestId("navigating-detail")).toHaveTextContent(
      "finding-2",
    );
    expect(useLighthouseContextStore.getState().focused?.id).toBe("finding-2");
  });
});
