"use client";

import { useMountEffect } from "@/hooks/use-mount-effect";
import { SIDEBAR_NAVIGATION_MODE, useSidebar } from "@/hooks/use-sidebar";
import { useSidePanelStore } from "@/store/side-panel";

export function LighthouseV2NavigationModeSync() {
  const setNavigationMode = useSidebar((state) => state.setNavigationMode);

  useMountEffect(() => {
    setNavigationMode(SIDEBAR_NAVIGATION_MODE.CHAT);
    // The full-page chat and the side panel are mutually exclusive: entering
    // this route closes the panel (it is also unmounted while here).
    useSidePanelStore.getState().closePanel();
  });

  return null;
}
