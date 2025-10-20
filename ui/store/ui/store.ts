import { create } from "zustand";
import { persist } from "zustand/middleware";

interface UIStoreState {
  isSideMenuOpen: boolean;
  isMutelistModalOpen: boolean;
  hasProviders: boolean;
  shouldAutoOpenMutelist: boolean;

  openSideMenu: () => void;
  closeSideMenu: () => void;
  openMutelistModal: () => void;
  closeMutelistModal: () => void;
  setHasProviders: (value: boolean) => void;
  requestMutelistModalOpen: () => void;
  resetMutelistModalRequest: () => void;
}

export const useUIStore = create<UIStoreState>()(
  persist(
    (set) => ({
      isSideMenuOpen: false,
      isMutelistModalOpen: false,
      hasProviders: false,
      shouldAutoOpenMutelist: false,
      openSideMenu: () => set({ isSideMenuOpen: true }),
      closeSideMenu: () => set({ isSideMenuOpen: false }),
      openMutelistModal: () =>
        set({
          isMutelistModalOpen: true,
          shouldAutoOpenMutelist: false,
        }),
      closeMutelistModal: () => set({ isMutelistModalOpen: false }),
      setHasProviders: (value: boolean) => set({ hasProviders: value }),
      requestMutelistModalOpen: () => set({ shouldAutoOpenMutelist: true }),
      resetMutelistModalRequest: () => set({ shouldAutoOpenMutelist: false }),
    }),
    {
      name: "ui-store",
    },
  ),
);
