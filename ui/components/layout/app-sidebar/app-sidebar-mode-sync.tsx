"use client";

import { useMountEffect } from "@/hooks/use-mount-effect";

import { useAppSidebarMode } from "./app-sidebar-mode-store";
import type { AppSidebarMode } from "./types";

interface AppSidebarModeSyncProps {
  mode: AppSidebarMode;
}

export function AppSidebarModeSync({ mode }: AppSidebarModeSyncProps) {
  const setMode = useAppSidebarMode((state) => state.setMode);

  useMountEffect(() => {
    setMode(mode);
  });

  return null;
}
