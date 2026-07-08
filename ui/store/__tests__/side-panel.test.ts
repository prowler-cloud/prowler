import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  SIDE_PANEL_DEFAULT_WIDTH,
  SIDE_PANEL_DETAIL_MIN_WIDTH,
  SIDE_PANEL_MIN_WIDTH,
} from "@/lib/ui-layout";
import { SIDE_PANEL_TAB, useSidePanelStore } from "@/store/side-panel";

describe("useSidePanelStore", () => {
  beforeEach(() => {
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

  it("opens the panel on the requested tab and latches hasBeenOpened", () => {
    // When
    useSidePanelStore.getState().openPanel(SIDE_PANEL_TAB.AI_CHAT);

    // Then
    const state = useSidePanelStore.getState();
    expect(state.isOpen).toBe(true);
    expect(state.selectedTab).toBe(SIDE_PANEL_TAB.AI_CHAT);
    expect(state.hasBeenOpened).toBe(true);
  });

  it("reopens on the last selected tab when no tab is given", () => {
    // Given
    useSidePanelStore.getState().openPanel(SIDE_PANEL_TAB.AI_CHAT);
    useSidePanelStore.getState().closePanel();

    // When
    useSidePanelStore.getState().openPanel();

    // Then
    expect(useSidePanelStore.getState().selectedTab).toBe(
      SIDE_PANEL_TAB.AI_CHAT,
    );
    expect(useSidePanelStore.getState().isOpen).toBe(true);
  });

  it("keeps content latched as mounted after closing", () => {
    // Given
    useSidePanelStore.getState().openPanel();

    // When
    useSidePanelStore.getState().closePanel();

    // Then
    expect(useSidePanelStore.getState().isOpen).toBe(false);
    expect(useSidePanelStore.getState().hasBeenOpened).toBe(true);
  });

  it("ignores a tab-scoped close for a tab that is not showing", () => {
    // Given
    useSidePanelStore.getState().openPanel(SIDE_PANEL_TAB.AI_CHAT);

    // When: a stale closer targets a different tab id
    useSidePanelStore.getState().closePanel(SIDE_PANEL_TAB.CONTEXT);

    // Then
    expect(useSidePanelStore.getState().isOpen).toBe(true);

    // When: the close targets the showing tab
    useSidePanelStore.getState().closePanel(SIDE_PANEL_TAB.AI_CHAT);

    // Then
    expect(useSidePanelStore.getState().isOpen).toBe(false);
  });

  it("toggles open and closed", () => {
    // When / Then
    useSidePanelStore.getState().togglePanel();
    expect(useSidePanelStore.getState().isOpen).toBe(true);
    expect(useSidePanelStore.getState().hasBeenOpened).toBe(true);

    useSidePanelStore.getState().togglePanel();
    expect(useSidePanelStore.getState().isOpen).toBe(false);
  });

  it("registering a context tab opens the panel on it", () => {
    // When
    useSidePanelStore.getState().registerContextTab({
      label: "Details",
      onRequestClose: vi.fn(),
    });

    // Then
    const state = useSidePanelStore.getState();
    expect(state.isOpen).toBe(true);
    expect(state.selectedTab).toBe(SIDE_PANEL_TAB.CONTEXT);
    expect(state.contextTab?.label).toBe("Details");
  });

  it("closing the panel asks the context owner to close its detail view", () => {
    // Given
    const onRequestClose = vi.fn();
    useSidePanelStore
      .getState()
      .registerContextTab({ label: "Details", onRequestClose });

    // When: the user dismisses the panel (X button / Escape)
    useSidePanelStore.getState().closePanel();

    // Then: the owning table is told to clear its selection
    expect(onRequestClose).toHaveBeenCalledTimes(1);
    expect(useSidePanelStore.getState().isOpen).toBe(false);
  });

  it("asks the context owner to close even while the AI tab is showing", () => {
    // Given: details registered, user switched to the AI tab
    const onRequestClose = vi.fn();
    useSidePanelStore
      .getState()
      .registerContextTab({ label: "Details", onRequestClose });
    useSidePanelStore.getState().openPanel(SIDE_PANEL_TAB.AI_CHAT);

    // When
    useSidePanelStore.getState().closePanel();

    // Then: dismissing the panel dismisses the detail view it hosts
    expect(onRequestClose).toHaveBeenCalledTimes(1);
  });

  it("unregistering the showing context tab closes the panel and falls back to AI", () => {
    // Given
    const token = useSidePanelStore.getState().registerContextTab({
      label: "Details",
      onRequestClose: vi.fn(),
    });

    // When
    useSidePanelStore.getState().unregisterContextTab(token);

    // Then
    const state = useSidePanelStore.getState();
    expect(state.contextTab).toBeNull();
    expect(state.isOpen).toBe(false);
    expect(state.selectedTab).toBe(SIDE_PANEL_TAB.AI_CHAT);
  });

  it("unregistering while the AI tab is showing keeps the panel open", () => {
    // Given: details registered but the user is chatting
    const token = useSidePanelStore.getState().registerContextTab({
      label: "Details",
      onRequestClose: vi.fn(),
    });
    useSidePanelStore.getState().openPanel(SIDE_PANEL_TAB.AI_CHAT);

    // When
    useSidePanelStore.getState().unregisterContextTab(token);

    // Then: the chat survives; only the Details tab disappears
    const state = useSidePanelStore.getState();
    expect(state.contextTab).toBeNull();
    expect(state.isOpen).toBe(true);
    expect(state.selectedTab).toBe(SIDE_PANEL_TAB.AI_CHAT);
  });

  it("replacing the context tab asks the previous owner to close itself", () => {
    // Given: finding A's detail view owns the context tab
    const closeA = vi.fn();
    useSidePanelStore
      .getState()
      .registerContextTab({ label: "Details", onRequestClose: closeA });

    // When: finding B's detail view registers
    const closeB = vi.fn();
    useSidePanelStore
      .getState()
      .registerContextTab({ label: "Details", onRequestClose: closeB });

    // Then: A is told to close; B stays untouched as the new owner
    expect(closeA).toHaveBeenCalledTimes(1);
    expect(closeB).not.toHaveBeenCalled();
    expect(useSidePanelStore.getState().contextTab?.onRequestClose).toBe(
      closeB,
    );
  });

  it("ignores an unregister from a replaced (stale) owner", () => {
    // Given: A registered, then B took over the context tab
    const tokenA = useSidePanelStore.getState().registerContextTab({
      label: "Details",
      onRequestClose: vi.fn(),
    });
    const tokenB = useSidePanelStore.getState().registerContextTab({
      label: "Details",
      onRequestClose: vi.fn(),
    });

    // When: A unmounts late and unregisters with its stale token
    useSidePanelStore.getState().unregisterContextTab(tokenA);

    // Then: B's registration survives
    const state = useSidePanelStore.getState();
    expect(state.contextTab).not.toBeNull();
    expect(state.contextOwnerToken).toBe(tokenB);
    expect(state.isOpen).toBe(true);

    // When: the current owner unregisters
    useSidePanelStore.getState().unregisterContextTab(tokenB);

    // Then
    expect(useSidePanelStore.getState().contextTab).toBeNull();
    expect(useSidePanelStore.getState().isOpen).toBe(false);
  });

  it("clamps resize widths to the allowed range", () => {
    // When: dragging far past both limits (jsdom viewport is 1024px wide)
    useSidePanelStore.getState().setWidth(100);
    expect(useSidePanelStore.getState().width).toBe(SIDE_PANEL_MIN_WIDTH);

    useSidePanelStore.getState().setWidth(5000);
    // Then: capped at 85% of the viewport
    expect(useSidePanelStore.getState().width).toBe(
      Math.floor(window.innerWidth * 0.85),
    );
  });

  it("widens to detail room when a context tab registers, keeping wider user choices", () => {
    // When: registering with the default (chat) width
    useSidePanelStore.getState().registerContextTab({
      label: "Details",
      onRequestClose: vi.fn(),
    });

    // Then
    expect(useSidePanelStore.getState().width).toBe(
      SIDE_PANEL_DETAIL_MIN_WIDTH,
    );

    // Given: the user resized wider than the detail minimum
    useSidePanelStore.getState().setWidth(800);

    // When
    useSidePanelStore.getState().registerContextTab({
      label: "Details",
      onRequestClose: vi.fn(),
    });

    // Then: the wider choice is respected
    expect(useSidePanelStore.getState().width).toBe(800);
  });

  it("persists only the selected tab and width, never open state nor the context tab", () => {
    // When: the context tab is the one selected
    useSidePanelStore.getState().registerContextTab({
      label: "Details",
      onRequestClose: vi.fn(),
    });

    // Then: a transient context selection is persisted as the AI tab
    const persisted = JSON.parse(
      localStorage.getItem("side-panel-store") ?? "{}",
    );
    expect(persisted.state).toEqual({
      selectedTab: SIDE_PANEL_TAB.AI_CHAT,
      width: SIDE_PANEL_DETAIL_MIN_WIDTH,
    });
    expect(persisted.state.isOpen).toBeUndefined();
    expect(persisted.state.contextTab).toBeUndefined();
  });
});
