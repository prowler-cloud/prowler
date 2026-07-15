import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { SIDE_PANEL_DEFAULT_WIDTH } from "@/lib/ui-layout";
import { SIDE_PANEL_TAB, useSidePanelStore } from "@/store/side-panel";

import { GlobalSidePanel } from "./global-side-panel";

const { isCloudMock } = vi.hoisted(() => ({ isCloudMock: vi.fn(() => true) }));

const navigationMocks = vi.hoisted(() => ({ pathname: "/findings" }));

// jsdom has no matchMedia: emulate the push (>= sm) viewport per test.
const mediaMocks = vi.hoisted(() => ({ isPushViewport: false }));

// Toggles a render failure to exercise the panel's local error boundary.
const chatMocks = vi.hoisted(() => ({ shouldThrow: false }));

vi.mock("@/lib/shared/env", () => ({ isCloud: isCloudMock }));

vi.mock("next/navigation", () => ({
  usePathname: () => navigationMocks.pathname,
}));

vi.mock("@/hooks/use-media-query", () => ({
  useMediaQuery: () => mediaMocks.isPushViewport,
}));

// The AI tab's real content pulls in the whole chat (server actions,
// streamdown); the shell test only cares that the registry's content mounts.
vi.mock(
  "@/app/(prowler)/lighthouse/_components/panel/lighthouse-panel-chat",
  () => ({
    LighthousePanelChat: () => {
      if (chatMocks.shouldThrow) throw new Error("chunk load failed");
      return <div data-testid="panel-chat-content">chat content</div>;
    },
  }),
);

describe("GlobalSidePanel", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  beforeEach(() => {
    isCloudMock.mockReturnValue(true);
    navigationMocks.pathname = "/findings";
    mediaMocks.isPushViewport = false;
    chatMocks.shouldThrow = false;
    localStorage.clear();
    useSidePanelStore.setState({
      isOpen: false,
      selectedTab: SIDE_PANEL_TAB.AI_CHAT,
      hasBeenOpened: false,
      width: SIDE_PANEL_DEFAULT_WIDTH,
      isResizing: false,
      contextTab: null,
      contextOwnerToken: 0,
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

  it("groups the chat actions beside close in the existing header", async () => {
    // Given
    render(<GlobalSidePanel />);

    // When
    act(() => useSidePanelStore.getState().openPanel());

    // Then: no extra toolbar; both actions are adjacent in the panel header
    const newChat = await screen.findByRole("button", { name: "New chat" });
    const fullPage = screen.getByRole("link", {
      name: "Open Lighthouse AI full page",
    });
    const close = screen.getByRole("button", { name: "Close side panel" });
    const actionGroup = close.parentElement;
    expect(actionGroup).toContainElement(newChat);
    expect(actionGroup).toContainElement(fullPage);
    expect(actionGroup).toHaveClass("ml-auto");
    expect(newChat).not.toHaveClass("ml-auto");
    expect(close).not.toHaveClass("ml-auto");
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
    expect(detailsTab).toHaveClass("aria-selected:after:scale-x-100");
    expect(detailsTab).not.toHaveClass("rounded-[8px]");
    expect(screen.getByTestId("side-panel-context-outlet")).toBeVisible();

    const lighthouseTab = screen.getByRole("tab", { name: "Lighthouse AI" });
    expect(lighthouseTab.querySelector("svg")?.parentElement).toHaveClass(
      "flex",
    );

    // When: switching to the AI tab
    await user.click(lighthouseTab);

    // Then: the chat mounts and the detail outlet stays mounted, hidden
    expect(await screen.findByTestId("panel-chat-content")).toBeInTheDocument();
    expect(screen.getByTestId("side-panel-context-outlet")).not.toBeVisible();

    // When: switching back
    await user.click(screen.getByRole("tab", { name: "Details" }));

    // Then
    expect(screen.getByTestId("side-panel-context-outlet")).toBeVisible();
  });

  it("contains a lazy tab failure inside the panel and recovers via Retry", async () => {
    // Given: the AI tab's content throws on render (e.g. chunk-load failure)
    const user = userEvent.setup();
    const consoleError = vi
      .spyOn(console, "error")
      .mockImplementation(() => {});
    chatMocks.shouldThrow = true;
    render(<GlobalSidePanel />);

    // When
    act(() => useSidePanelStore.getState().openPanel(SIDE_PANEL_TAB.AI_CHAT));

    // Then: the failure stays inside the panel body; the shell survives
    expect(
      await screen.findByText("This panel failed to load."),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Close side panel" }),
    ).toBeInTheDocument();

    // When: the failure clears and the user retries
    chatMocks.shouldThrow = false;
    await user.click(screen.getByRole("button", { name: "Retry" }));

    // Then: the content mounts normally
    expect(await screen.findByTestId("panel-chat-content")).toBeInTheDocument();
    consoleError.mockRestore();
  });

  it("re-clamps a persisted oversized width to the current viewport", () => {
    // Given: a huge width rehydrated raw from a larger monitor
    mediaMocks.isPushViewport = true;
    useSidePanelStore.setState({ width: 5000 });
    render(<GlobalSidePanel />);

    // When
    act(() => useSidePanelStore.getState().openPanel());

    // Then: applied width is capped at 85% of this viewport
    expect(screen.getByTestId("global-side-panel")).toHaveStyle({
      width: `${Math.floor(window.innerWidth * 0.85)}px`,
    });
  });

  it("resizes with arrow keys on the handle (left widens, right narrows)", async () => {
    // Given
    mediaMocks.isPushViewport = true;
    const user = userEvent.setup();
    render(<GlobalSidePanel />);
    act(() => useSidePanelStore.getState().openPanel());
    const handle = screen.getByRole("separator", { name: "Resize panel" });
    expect(handle).toHaveAttribute(
      "aria-valuenow",
      String(SIDE_PANEL_DEFAULT_WIDTH),
    );

    // When / Then
    act(() => handle.focus());
    await user.keyboard("{ArrowLeft}");
    expect(useSidePanelStore.getState().width).toBe(
      SIDE_PANEL_DEFAULT_WIDTH + 24,
    );

    await user.keyboard("{ArrowRight}");
    expect(useSidePanelStore.getState().width).toBe(SIDE_PANEL_DEFAULT_WIDTH);
  });

  it("exposes half the viewport as the resize maximum on ultra-wide screens", () => {
    // Given
    vi.stubGlobal("innerWidth", 2560);
    mediaMocks.isPushViewport = true;
    useSidePanelStore.setState({ width: 5000 });

    // When
    render(<GlobalSidePanel />);

    // Then
    expect(screen.getByTestId("global-side-panel")).toHaveStyle({
      width: "1280px",
    });
    expect(
      screen.getByRole("separator", { name: "Resize panel" }),
    ).toHaveAttribute("aria-valuemax", "1280");
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

  it("remains available on Lighthouse settings", () => {
    // Given: settings must coexist with the panel, unlike the chat page
    navigationMocks.pathname = "/lighthouse/settings";
    useSidePanelStore.setState({ isOpen: true, hasBeenOpened: true });

    // When
    render(<GlobalSidePanel />);

    // Then
    expect(screen.getByTestId("global-side-panel")).toHaveClass(
      "translate-x-0",
    );
  });
});
