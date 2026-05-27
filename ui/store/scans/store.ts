import { create } from "zustand";

interface ScansStoreState {
  isLaunchScanModalOpen: boolean;
  setLaunchScanModalOpen: (open: boolean) => void;
  openLaunchScanModal: () => void;
  closeLaunchScanModal: () => void;
}

// Modal state is ephemeral; intentionally not persisted across reloads.
export const useScansStore = create<ScansStoreState>((set) => ({
  isLaunchScanModalOpen: false,
  setLaunchScanModalOpen: (open) => set({ isLaunchScanModalOpen: open }),
  openLaunchScanModal: () => set({ isLaunchScanModalOpen: true }),
  closeLaunchScanModal: () => set({ isLaunchScanModalOpen: false }),
}));
