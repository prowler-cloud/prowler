import { create } from "zustand";
import { persist } from "zustand/middleware";

interface UIStoreState {
  isSideMenuOpen: boolean;
  hasProviders: boolean;
  // True once the server reported a definitive provider count for this session.
  hasProvidersResolved: boolean;
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
      hasProvidersResolved: false,
      registryEligible: false,
      openSideMenu: () => set({ isSideMenuOpen: true }),
      closeSideMenu: () => set({ isSideMenuOpen: false }),
      setHasProviders: (value: boolean) =>
        set({ hasProviders: value, hasProvidersResolved: true }),
      setRegistryEligible: (value: boolean) => set({ registryEligible: value }),
    }),
    {
      name: "ui-store",
      // Registry eligibility and the provider-count resolution are per-request
      // server decisions; persisting them would resurface a stale entry on the
      // next session before the server seed corrects it.
      partialize: ({ isSideMenuOpen, hasProviders }) => ({
        isSideMenuOpen,
        hasProviders,
      }),
    },
  ),
);
