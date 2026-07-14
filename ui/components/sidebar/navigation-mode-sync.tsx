"use client";

import { useMountEffect } from "@/hooks/use-mount-effect";
import { type SidebarNavigationMode, useSidebar } from "@/hooks/use-sidebar";
import { useSidePanelStore } from "@/store/side-panel";

interface SidebarNavigationModeSyncProps {
  mode: SidebarNavigationMode;
  closeSidePanel?: boolean;
}

export function SidebarNavigationModeSync({
  mode,
  closeSidePanel = false,
}: SidebarNavigationModeSyncProps) {
  const setNavigationMode = useSidebar((state) => state.setNavigationMode);

  useMountEffect(() => {
    setNavigationMode(mode);
    if (closeSidePanel) {
      useSidePanelStore.getState().closePanel();
    }
  });

  return null;
}
