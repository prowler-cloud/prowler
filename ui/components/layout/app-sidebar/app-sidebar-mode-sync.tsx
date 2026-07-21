"use client";

import { useMountEffect } from "@/hooks/use-mount-effect";
import { useSidePanelStore } from "@/store/side-panel";

import { useAppSidebarMode } from "./app-sidebar-mode-store";
import type { AppSidebarMode } from "./types";

interface AppSidebarModeSyncProps {
  mode: AppSidebarMode;
  // The full-page chat dismisses the side panel: the chat lives in one place
  // or the other, never both.
  closeSidePanel?: boolean;
}

export function AppSidebarModeSync({
  mode,
  closeSidePanel = false,
}: AppSidebarModeSyncProps) {
  const setMode = useAppSidebarMode((state) => state.setMode);

  useMountEffect(() => {
    setMode(mode);
    if (closeSidePanel) {
      useSidePanelStore.getState().closePanel();
    }
  });

  return null;
}
