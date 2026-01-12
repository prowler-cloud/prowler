import { create } from "zustand";
import { persist } from "zustand/middleware";

interface UIStoreState {
  isSideMenuOpen: boolean;
  hasProviders: boolean;

  openSideMenu: () => void;
  closeSideMenu: () => void;
  setHasProviders: (value: boolean) => void;
}

export const useUIStore = create<UIStoreState>()(
  persist(
    (set) => ({
      isSideMenuOpen: false,
      hasProviders: false,
      openSideMenu: () => set({ isSideMenuOpen: true }),
      closeSideMenu: () => set({ isSideMenuOpen: false }),
      setHasProviders: (value: boolean) => set({ hasProviders: value }),
    }),
    {
      name: "ui-store",
    },
  ),
);
