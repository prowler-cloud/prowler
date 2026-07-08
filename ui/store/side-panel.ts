import { create } from "zustand";
import { persist } from "zustand/middleware";

import {
  clampSidePanelWidth,
  SIDE_PANEL_DEFAULT_WIDTH,
  SIDE_PANEL_DETAIL_MIN_WIDTH,
} from "@/lib/ui-layout";

export const SIDE_PANEL_TAB = {
  AI_CHAT: "ai-chat",
  // Dynamic tab registered by the page currently showing a detail view
  // (finding/resource). Never persisted and never in the static registry.
  CONTEXT: "context",
} as const;

export type SidePanelTabId =
  (typeof SIDE_PANEL_TAB)[keyof typeof SIDE_PANEL_TAB];

interface SidePanelContextTab {
  label: string;
  // Called when the panel is dismissed so the owning table can clear its
  // selection (the owner controls `open`; the panel never owns detail state).
  onRequestClose: () => void;
}

interface SidePanelState {
  isOpen: boolean;
  selectedTab: SidePanelTabId;
  // Lazy-mount latch: panel content mounts on first open and then stays
  // mounted (hidden) so scroll position and composer drafts survive closes.
  hasBeenOpened: boolean;
  // User-resizable width in px (persisted); MainLayout pushes by this amount.
  width: number;
  isResizing: boolean;
  contextTab: SidePanelContextTab | null;
  // Token of the current context-tab owner (0 = none): several detail views
  // can be mounted at once, but only the owner portals content and only the
  // owner's unregister takes effect.
  contextOwnerToken: number;
  // Portal target the context owner renders its detail content into.
  contextOutlet: HTMLElement | null;
  openPanel: (tab?: SidePanelTabId) => void;
  closePanel: (tab?: SidePanelTabId) => void;
  togglePanel: () => void;
  setWidth: (width: number) => void;
  setIsResizing: (isResizing: boolean) => void;
  registerContextTab: (tab: SidePanelContextTab) => number;
  unregisterContextTab: (token: number) => void;
  setContextOutlet: (element: HTMLElement | null) => void;
}

// Monotonic so a recycled token can never let a stale detail view unregister
// (or portal over) a later registrant.
let contextTabTokenCounter = 0;

export const useSidePanelStore = create<SidePanelState>()(
  persist(
    (set, get) => ({
      isOpen: false,
      selectedTab: SIDE_PANEL_TAB.AI_CHAT,
      hasBeenOpened: false,
      width: SIDE_PANEL_DEFAULT_WIDTH,
      isResizing: false,
      contextTab: null,
      contextOwnerToken: 0,
      contextOutlet: null,
      openPanel: (tab) =>
        set({
          isOpen: true,
          hasBeenOpened: true,
          selectedTab: tab ?? get().selectedTab,
        }),
      // Tab-scoped close only applies while that tab is showing, so a stale
      // closer never hides a panel someone else switched to another tab.
      closePanel: (tab) => {
        const { selectedTab, contextTab } = get();
        if (tab && tab !== selectedTab) return;
        set({ isOpen: false });
        // Dismissing the panel dismisses the detail view it hosts.
        contextTab?.onRequestClose();
      },
      togglePanel: () => {
        const { isOpen } = get();
        if (isOpen) {
          get().closePanel();
          return;
        }
        set({ isOpen: true, hasBeenOpened: true });
      },
      setWidth: (width) => set({ width: clampSidePanelWidth(width) }),
      setIsResizing: (isResizing) => set({ isResizing }),
      registerContextTab: (tab) => {
        // A new detail view takes over the single context tab: ask the
        // previous owner to close itself so it clears its own selection.
        get().contextTab?.onRequestClose();
        const token = ++contextTabTokenCounter;
        set((state) => ({
          contextTab: tab,
          contextOwnerToken: token,
          selectedTab: SIDE_PANEL_TAB.CONTEXT,
          isOpen: true,
          hasBeenOpened: true,
          // Detail content needs drawer-like room; never shrink a wider
          // user-chosen width.
          width: clampSidePanelWidth(
            Math.max(state.width, SIDE_PANEL_DETAIL_MIN_WIDTH),
          ),
        }));
        return token;
      },
      unregisterContextTab: (token) => {
        // Only the current owner may unregister: a replaced detail view
        // unmounting later must not tear down its successor.
        if (token !== get().contextOwnerToken) return;
        set((state) => ({
          contextTab: null,
          contextOwnerToken: 0,
          // When the detail tab was showing, its content is gone: close the
          // panel and leave the AI tab as the next default.
          ...(state.selectedTab === SIDE_PANEL_TAB.CONTEXT
            ? { isOpen: false, selectedTab: SIDE_PANEL_TAB.AI_CHAT }
            : {}),
        }));
      },
      setContextOutlet: (element) => set({ contextOutlet: element }),
    }),
    {
      name: "side-panel-store",
      // Only the last-used tab and width persist; the panel never auto-reopens
      // and a context tab cannot exist on a fresh load.
      partialize: (state) => ({
        selectedTab:
          state.selectedTab === SIDE_PANEL_TAB.CONTEXT
            ? SIDE_PANEL_TAB.AI_CHAT
            : state.selectedTab,
        width: state.width,
      }),
    },
  ),
);
