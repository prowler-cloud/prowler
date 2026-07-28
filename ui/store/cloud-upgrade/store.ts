import { create } from "zustand";

import {
  CLOUD_UPGRADE_FEATURE,
  type CloudUpgradeFeature,
} from "@/types/cloud-upgrade";

interface CloudUpgradeStoreState {
  activeFeature: CloudUpgradeFeature | null;
  retainedFeature: CloudUpgradeFeature;
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
  retainedFeature: CLOUD_UPGRADE_FEATURE.GENERAL,
  returnFocusElement: null,
  openCloudUpgrade: (activeFeature, requestedReturnFocusElement) =>
    set({
      activeFeature,
      retainedFeature: activeFeature,
      returnFocusElement:
        requestedReturnFocusElement ??
        (document.activeElement instanceof HTMLElement
          ? document.activeElement
          : null),
    }),
  closeCloudUpgrade: () => set({ activeFeature: null }),
}));
