"use client";

import { useMountEffect } from "@/hooks/use-mount-effect";
import { SIDEBAR_NAVIGATION_MODE, useSidebar } from "@/hooks/use-sidebar";

export function LighthouseV2NavigationModeSync() {
  const setNavigationMode = useSidebar((state) => state.setNavigationMode);

  useMountEffect(() => {
    setNavigationMode(SIDEBAR_NAVIGATION_MODE.CHAT);
  });

  return null;
}
