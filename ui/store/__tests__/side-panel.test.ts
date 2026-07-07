import { beforeEach, describe, expect, it } from "vitest";

import { SIDE_PANEL_TAB, useSidePanelStore } from "@/store/side-panel";

describe("useSidePanelStore", () => {
  beforeEach(() => {
    localStorage.clear();
    useSidePanelStore.setState({
      isOpen: false,
      selectedTab: SIDE_PANEL_TAB.AI_CHAT,
      hasBeenOpened: false,
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
    useSidePanelStore
      .getState()
      .closePanel("some-future-tab" as typeof SIDE_PANEL_TAB.AI_CHAT);

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

  it("persists only the selected tab, never the open state", () => {
    // When
    useSidePanelStore.getState().openPanel(SIDE_PANEL_TAB.AI_CHAT);

    // Then
    const persisted = JSON.parse(localStorage.getItem("side-panel") ?? "{}");
    expect(persisted.state).toEqual({ selectedTab: SIDE_PANEL_TAB.AI_CHAT });
    expect(persisted.state.isOpen).toBeUndefined();
  });
});
