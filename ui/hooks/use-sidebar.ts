import { create } from "zustand";
import { createJSONStorage, persist } from "zustand/middleware";

export const SIDEBAR_NAVIGATION_MODE = {
  BROWSE: "browse",
  CHAT: "chat",
} as const;

export type SidebarNavigationMode =
  (typeof SIDEBAR_NAVIGATION_MODE)[keyof typeof SIDEBAR_NAVIGATION_MODE];

type SidebarSettings = { disabled: boolean; isHoverOpen: boolean };
type SidebarStore = {
  isOpen: boolean;
  isHover: boolean;
  navigationMode: SidebarNavigationMode;
  settings: SidebarSettings;
  toggleOpen: () => void;
  setIsOpen: (isOpen: boolean) => void;
  setIsHover: (isHover: boolean) => void;
  setNavigationMode: (navigationMode: SidebarNavigationMode) => void;
  getOpenState: () => boolean;
};

export const useSidebar = create(
  persist<SidebarStore>(
    (set, get) => ({
      isOpen: true,
      isHover: false,
      navigationMode: SIDEBAR_NAVIGATION_MODE.BROWSE,
      settings: { disabled: false, isHoverOpen: false },
      toggleOpen: () => {
        set({ isOpen: !get().isOpen });
      },
      setIsOpen: (isOpen: boolean) => {
        set({ isOpen });
      },
      setIsHover: (isHover: boolean) => {
        set({ isHover });
      },
      setNavigationMode: (navigationMode: SidebarNavigationMode) => {
        set({ navigationMode });
      },
      getOpenState: () => {
        const state = get();
        return state.isOpen || (state.settings.isHoverOpen && state.isHover);
      },
    }),
    {
      name: "sidebar",
      storage: createJSONStorage(() => localStorage),
    },
  ),
);
