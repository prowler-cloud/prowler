import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { SIDE_PANEL_TAB, useSidePanelStore } from "@/store/side-panel";

import { GlobalSidePanel } from "./global-side-panel";

const { isCloudMock } = vi.hoisted(() => ({ isCloudMock: vi.fn(() => true) }));

const navigationMocks = vi.hoisted(() => ({ pathname: "/findings" }));

vi.mock("@/lib/shared/env", () => ({ isCloud: isCloudMock }));

vi.mock("next/navigation", () => ({
  usePathname: () => navigationMocks.pathname,
}));

// The AI tab's real content pulls in the whole chat (server actions,
// streamdown); the shell test only cares that the registry's content mounts.
vi.mock(
  "@/app/(prowler)/lighthouse/_components/panel/lighthouse-panel-chat",
  () => ({
    LighthousePanelChat: () => (
      <div data-testid="panel-chat-content">chat content</div>
    ),
  }),
);

describe("GlobalSidePanel", () => {
  beforeEach(() => {
    isCloudMock.mockReturnValue(true);
    navigationMocks.pathname = "/findings";
    localStorage.clear();
    useSidePanelStore.setState({
      isOpen: false,
      selectedTab: SIDE_PANEL_TAB.AI_CHAT,
      hasBeenOpened: false,
      contextTab: null,
      contextOutlet: null,
    });
  });

  it("renders closed and empty by default (lazy-mount)", () => {
    // Given / When
    render(<GlobalSidePanel />);

    // Then: panel exists but is off-screen, inert, and mounts no content
    const panel = screen.getByTestId("global-side-panel");
    expect(panel).toHaveClass("translate-x-full");
    expect(screen.queryByTestId("panel-chat-content")).not.toBeInTheDocument();
  });

  it("slides in and mounts the AI tab content when opened via the store", async () => {
    // Given
    render(<GlobalSidePanel />);

    // When
    act(() => useSidePanelStore.getState().openPanel(SIDE_PANEL_TAB.AI_CHAT));

    // Then
    expect(screen.getByTestId("global-side-panel")).toHaveClass(
      "translate-x-0",
    );
    expect(await screen.findByTestId("panel-chat-content")).toBeInTheDocument();
  });

  it("keeps the content mounted (hidden) after closing", async () => {
    // Given
    render(<GlobalSidePanel />);
    act(() => useSidePanelStore.getState().openPanel());
    await screen.findByTestId("panel-chat-content");

    // When
    act(() => useSidePanelStore.getState().closePanel());

    // Then: off-screen but the chat DOM survives (scroll/draft preservation)
    expect(screen.getByTestId("global-side-panel")).toHaveClass(
      "translate-x-full",
    );
    expect(screen.getByTestId("panel-chat-content")).toBeInTheDocument();
  });

  it("closes on Escape", async () => {
    // Given
    const user = userEvent.setup();
    render(<GlobalSidePanel />);
    act(() => useSidePanelStore.getState().openPanel());

    // When
    await user.keyboard("{Escape}");

    // Then
    await waitFor(() =>
      expect(useSidePanelStore.getState().isOpen).toBe(false),
    );
  });

  it("toggles with Cmd/Ctrl+.", async () => {
    // Given
    const user = userEvent.setup();
    render(<GlobalSidePanel />);

    // When / Then
    await user.keyboard("{Meta>}.{/Meta}");
    expect(useSidePanelStore.getState().isOpen).toBe(true);

    await user.keyboard("{Meta>}.{/Meta}");
    expect(useSidePanelStore.getState().isOpen).toBe(false);
  });

  it("closes via the close button", async () => {
    // Given
    const user = userEvent.setup();
    render(<GlobalSidePanel />);
    act(() => useSidePanelStore.getState().openPanel());

    // When
    await user.click(screen.getByRole("button", { name: "Close side panel" }));

    // Then
    expect(useSidePanelStore.getState().isOpen).toBe(false);
  });

  it("renders nothing in OSS while no detail view is registered", () => {
    // Given
    isCloudMock.mockReturnValue(false);

    // When
    const { container } = render(<GlobalSidePanel />);

    // Then
    expect(container).toBeEmptyDOMElement();
  });

  it("hosts a registered detail view in OSS, without the AI tab", () => {
    // Given
    isCloudMock.mockReturnValue(false);
    render(<GlobalSidePanel />);

    // When: a detail view registers its context tab
    act(() =>
      useSidePanelStore.getState().registerContextTab({
        label: "Details",
        onRequestClose: vi.fn(),
      }),
    );

    // Then: the panel appears with only the Details surface (no tab strip)
    expect(screen.getByTestId("global-side-panel")).toHaveClass(
      "translate-x-0",
    );
    expect(screen.getByText("Details")).toBeInTheDocument();
    expect(screen.queryByRole("tablist")).not.toBeInTheDocument();
    expect(screen.getByTestId("side-panel-context-outlet")).toBeInTheDocument();
  });

  it("shows Details and Lighthouse AI as switchable tabs in cloud", async () => {
    // Given
    const user = userEvent.setup();
    render(<GlobalSidePanel />);
    act(() =>
      useSidePanelStore.getState().registerContextTab({
        label: "Details",
        onRequestClose: vi.fn(),
      }),
    );

    // Then: the context tab opens selected, beside the AI tab
    const detailsTab = screen.getByRole("tab", { name: "Details" });
    expect(detailsTab).toHaveAttribute("aria-selected", "true");
    expect(screen.getByTestId("side-panel-context-outlet")).toBeVisible();

    // When: switching to the AI tab
    await user.click(screen.getByRole("tab", { name: "Lighthouse AI" }));

    // Then: the chat mounts and the detail outlet stays mounted, hidden
    expect(await screen.findByTestId("panel-chat-content")).toBeInTheDocument();
    expect(screen.getByTestId("side-panel-context-outlet")).not.toBeVisible();

    // When: switching back
    await user.click(screen.getByRole("tab", { name: "Details" }));

    // Then
    expect(screen.getByTestId("side-panel-context-outlet")).toBeVisible();
  });

  it("does not exist on the full-page chat route (one place or the other)", () => {
    // Given: the user is on the agentic chat page with the panel open
    navigationMocks.pathname = "/lighthouse";
    useSidePanelStore.setState({ isOpen: true, hasBeenOpened: true });

    // When
    const { container } = render(<GlobalSidePanel />);

    // Then: no panel DOM at all — the chat lives in the page there
    expect(container).toBeEmptyDOMElement();
  });
});
