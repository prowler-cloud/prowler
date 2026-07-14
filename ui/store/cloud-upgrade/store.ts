import { create } from "zustand";

import type { CloudUpgradeFeature } from "@/lib/cloud-upgrade";

interface CloudUpgradeStoreState {
  activeFeature: CloudUpgradeFeature | null;
  returnFocusElement: HTMLElement | null;
  openCloudUpgrade: (feature: CloudUpgradeFeature) => void;
  closeCloudUpgrade: () => void;
}

// Upgrade prompts are ephemeral and shared so only one modal can be open.
export const useCloudUpgradeStore = create<CloudUpgradeStoreState>((set) => ({
  activeFeature: null,
  returnFocusElement: null,
  openCloudUpgrade: (activeFeature) =>
    set({
      activeFeature,
      returnFocusElement:
        document.activeElement instanceof HTMLElement
          ? document.activeElement
          : null,
    }),
  closeCloudUpgrade: () => set({ activeFeature: null }),
}));
