"use client";

import { useMountEffect } from "@/hooks/use-mount-effect";
import { type SidebarNavigationMode, useSidebar } from "@/hooks/use-sidebar";

interface SidebarNavigationModeSyncProps {
  mode: SidebarNavigationMode;
}

export function SidebarNavigationModeSync({
  mode,
}: SidebarNavigationModeSyncProps) {
  const setNavigationMode = useSidebar((state) => state.setNavigationMode);

  useMountEffect(() => {
    setNavigationMode(mode);
  });

  return null;
}
