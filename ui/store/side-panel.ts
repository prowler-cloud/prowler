import { create } from "zustand";
import { persist } from "zustand/middleware";

export const SIDE_PANEL_TAB = {
  AI_CHAT: "ai-chat",
} as const;

export type SidePanelTabId =
  (typeof SIDE_PANEL_TAB)[keyof typeof SIDE_PANEL_TAB];

interface SidePanelState {
  isOpen: boolean;
  selectedTab: SidePanelTabId;
  // Lazy-mount latch: panel content mounts on first open and then stays
  // mounted (hidden) so scroll position and composer drafts survive closes.
  hasBeenOpened: boolean;
  openPanel: (tab?: SidePanelTabId) => void;
  closePanel: (tab?: SidePanelTabId) => void;
  togglePanel: () => void;
}

export const useSidePanelStore = create<SidePanelState>()(
  persist(
    (set, get) => ({
      isOpen: false,
      selectedTab: SIDE_PANEL_TAB.AI_CHAT,
      hasBeenOpened: false,
      openPanel: (tab) =>
        set({
          isOpen: true,
          hasBeenOpened: true,
          selectedTab: tab ?? get().selectedTab,
        }),
      // Tab-scoped close only applies while that tab is showing, so a stale
      // closer never hides a panel someone else switched to another tab.
      closePanel: (tab) => {
        if (tab && tab !== get().selectedTab) return;
        set({ isOpen: false });
      },
      togglePanel: () => {
        const { isOpen } = get();
        set(isOpen ? { isOpen: false } : { isOpen: true, hasBeenOpened: true });
      },
    }),
    {
      name: "side-panel",
      // Only the last-used tab persists; the panel never auto-reopens.
      partialize: (state) => ({ selectedTab: state.selectedTab }),
    },
  ),
);
