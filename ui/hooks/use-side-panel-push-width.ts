"use client";

import { usePathname } from "next/navigation";

import { useMediaQuery } from "@/hooks/use-media-query";
import { useStore } from "@/hooks/use-store";
import { isLighthouseChatRoute } from "@/lib/lighthouse-routes";
import {
  clampSidePanelWidth,
  SIDE_PANEL_PUSH_MEDIA_QUERY,
} from "@/lib/ui-layout";
import { useSidePanelStore } from "@/store/side-panel";

// Pixels the open side panel takes from the right edge; undefined while it is
// closed, overlays full-width (below `sm`) or does not exist (full-page chat).
export function useSidePanelPushWidth(): number | undefined {
  const pathname = usePathname();
  const isOpen = useStore(useSidePanelStore, (state) => state.isOpen);
  const width = useStore(useSidePanelStore, (state) => state.width);
  const isPushViewport = useMediaQuery(SIDE_PANEL_PUSH_MEDIA_QUERY);

  if (!isOpen || width === undefined || !isPushViewport) return undefined;
  if (isLighthouseChatRoute(pathname)) return undefined;
  // Re-clamp at consumption: a persisted width from a larger monitor
  // rehydrates raw and would otherwise collapse the page on this viewport.
  return clampSidePanelWidth(width);
}
