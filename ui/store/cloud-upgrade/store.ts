import { create } from "zustand";

import type { CloudUpgradeFeature } from "@/types/cloud-upgrade";

interface CloudUpgradeStoreState {
  activeFeature: CloudUpgradeFeature | null;
  returnFocusElement: HTMLElement | null;
  openCloudUpgrade: (
    feature: CloudUpgradeFeature,
    returnFocusElement?: HTMLElement,
  ) => void;
  closeCloudUpgrade: () => void;
}

// Upgrade prompts are ephemeral and shared so only one modal can be open.
export const useCloudUpgradeStore = create<CloudUpgradeStoreState>((set) => ({
  activeFeature: null,
  returnFocusElement: null,
  openCloudUpgrade: (activeFeature, requestedReturnFocusElement) =>
    set({
      activeFeature,
      returnFocusElement:
        requestedReturnFocusElement ??
        (document.activeElement instanceof HTMLElement
          ? document.activeElement
          : null),
    }),
  closeCloudUpgrade: () => set({ activeFeature: null }),
}));
