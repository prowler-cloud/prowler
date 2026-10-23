import { create } from "zustand";

import type { PartialScanTarget } from "@/types/partial-scans";

interface PartialScanStoreState {
  activeTarget: PartialScanTarget | null;
  openPartialScan: (target: PartialScanTarget) => void;
  closePartialScan: () => void;
}

// Menu items live inside dropdowns that unmount on select, so the confirmation
// modal is hosted once globally and driven through this store.
export const usePartialScanStore = create<PartialScanStoreState>((set) => ({
  activeTarget: null,
  openPartialScan: (activeTarget) => set({ activeTarget }),
  closePartialScan: () => set({ activeTarget: null }),
}));
