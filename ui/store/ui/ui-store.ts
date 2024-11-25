import { create } from "zustand";
import { persist } from "zustand/middleware";

interface SidebarStoreState {
  isSideMenuOpen: boolean;

  openSideMenu: () => void;
  closeSideMenu: () => void;
}

export const useUIStore = create<SidebarStoreState>()(
  persist(
    (set) => ({
      isSideMenuOpen: false,
      openSideMenu: () => set({ isSideMenuOpen: true }),
      closeSideMenu: () => set({ isSideMenuOpen: false }),
    }),
    {
      name: "sidebar-store",
    },
  ),
);
