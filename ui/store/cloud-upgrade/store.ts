import { create } from "zustand";

import {
  CLOUD_UPGRADE_FEATURE,
  CLOUD_UPGRADE_SURFACE,
  type CloudUpgradeSurface,
  type UpgradeFeature,
} from "@/types/cloud-upgrade";

interface CloudUpgradeStoreState {
  activeFeature: UpgradeFeature | null;
  retainedFeature: UpgradeFeature;
  surface: CloudUpgradeSurface;
  returnFocusElement: HTMLElement | null;
  openCloudUpgrade: (
    feature: UpgradeFeature,
    returnFocusElement?: HTMLElement,
    surface?: CloudUpgradeSurface,
  ) => void;
  closeCloudUpgrade: () => void;
}

// Upgrade prompts are ephemeral and shared so only one modal can be open.
export const useCloudUpgradeStore = create<CloudUpgradeStoreState>((set) => ({
  activeFeature: null,
  retainedFeature: CLOUD_UPGRADE_FEATURE.GENERAL,
  surface: CLOUD_UPGRADE_SURFACE.BADGE,
  returnFocusElement: null,
  openCloudUpgrade: (
    activeFeature,
    requestedReturnFocusElement,
    surface = CLOUD_UPGRADE_SURFACE.BADGE,
  ) =>
    set({
      activeFeature,
      retainedFeature: activeFeature,
      surface,
      returnFocusElement:
        requestedReturnFocusElement ??
        (document.activeElement instanceof HTMLElement
          ? document.activeElement
          : null),
    }),
  closeCloudUpgrade: () => set({ activeFeature: null }),
}));
