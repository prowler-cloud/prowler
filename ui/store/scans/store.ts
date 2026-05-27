import { create } from "zustand";

interface ScansStoreState {
  isLaunchScanModalOpen: boolean;
  setLaunchScanModalOpen: (open: boolean) => void;
  openLaunchScanModal: () => void;
  closeLaunchScanModal: () => void;
}

export const useScansStore = create<ScansStoreState>((set) => ({
  isLaunchScanModalOpen: false,
  setLaunchScanModalOpen: (open) => set({ isLaunchScanModalOpen: open }),
  openLaunchScanModal: () => set({ isLaunchScanModalOpen: true }),
  closeLaunchScanModal: () => set({ isLaunchScanModalOpen: false }),
}));
