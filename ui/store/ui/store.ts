import { create } from "zustand";
import { persist } from "zustand/middleware";

interface UIStoreState {
  isSideMenuOpen: boolean;
  hasProviders: boolean;
  registryEligible: boolean;

  openSideMenu: () => void;
  closeSideMenu: () => void;
  setHasProviders: (value: boolean) => void;
  setRegistryEligible: (value: boolean) => void;
}

export const useUIStore = create<UIStoreState>()(
  persist(
    (set) => ({
      isSideMenuOpen: false,
      hasProviders: false,
      registryEligible: false,
      openSideMenu: () => set({ isSideMenuOpen: true }),
      closeSideMenu: () => set({ isSideMenuOpen: false }),
      setHasProviders: (value: boolean) => set({ hasProviders: value }),
      setRegistryEligible: (value: boolean) => set({ registryEligible: value }),
    }),
    {
      name: "ui-store",
      // Registry eligibility is a per-request server decision; persisting it
      // would resurface a stale entry on the next session before the server
      // seed corrects it.
      partialize: ({ isSideMenuOpen, hasProviders }) => ({
        isSideMenuOpen,
        hasProviders,
      }),
    },
  ),
);
