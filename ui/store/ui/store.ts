import { create } from "zustand";
import { persist } from "zustand/middleware";

interface UIStoreState {
  isSideMenuOpen: boolean;
  isMutelistModalOpen: boolean;
  hasProviders: boolean;

  openSideMenu: () => void;
  closeSideMenu: () => void;
  openMutelistModal: () => void;
  closeMutelistModal: () => void;
  setHasProviders: (value: boolean) => void;
}

export const useUIStore = create<UIStoreState>()(
  persist(
    (set) => ({
      isSideMenuOpen: false,
      isMutelistModalOpen: false,
      hasProviders: false,
      openSideMenu: () => set({ isSideMenuOpen: true }),
      closeSideMenu: () => set({ isSideMenuOpen: false }),
      openMutelistModal: () => set({ isMutelistModalOpen: true }),
      closeMutelistModal: () => set({ isMutelistModalOpen: false }),
      setHasProviders: (value: boolean) => set({ hasProviders: value }),
    }),
    {
      name: "ui-store",
    },
  ),
);
