"use client";

import type { ComponentType } from "react";

import { LighthousePanelChatSkeleton } from "@/app/(prowler)/lighthouse/_components/panel/lighthouse-panel-chat-skeleton";
import { LighthousePanelHeaderActions } from "@/app/(prowler)/lighthouse/_components/panel/lighthouse-panel-header-actions";
import { LighthouseIcon } from "@/components/icons";
import { isCloud } from "@/lib/shared/env";
import { SIDE_PANEL_TAB, type SidePanelTabId } from "@/store/side-panel";

// The CONTEXT tab is dynamic (registered at runtime by detail views), so the
// static registry only holds the fixed tabs.
type RegistrySidePanelTabId = Exclude<
  SidePanelTabId,
  typeof SIDE_PANEL_TAB.CONTEXT
>;

interface SidePanelTabDefinition {
  id: RegistrySidePanelTabId;
  label: string;
  Icon: ComponentType<{ className?: string }>;
  // Kept as a loader so Retry can create a fresh React.lazy instance after a
  // rejected chunk request instead of reusing React's cached rejection.
  loadContent: () => Promise<{ default: ComponentType }>;
  // Eager (lightweight) 1:1 skeleton shown while Content's bundle downloads.
  Fallback: ComponentType;
  HeaderActions?: ComponentType;
  isAvailable: () => boolean;
}

export const SIDE_PANEL_TABS: Record<
  RegistrySidePanelTabId,
  SidePanelTabDefinition
> = {
  [SIDE_PANEL_TAB.AI_CHAT]: {
    id: SIDE_PANEL_TAB.AI_CHAT,
    label: "Lighthouse AI",
    Icon: LighthouseIcon,
    loadContent: () =>
      import(
        "@/app/(prowler)/lighthouse/_components/panel/lighthouse-panel-chat"
      ).then((module) => ({ default: module.LighthousePanelChat })),
    Fallback: LighthousePanelChatSkeleton,
    HeaderActions: LighthousePanelHeaderActions,
    isAvailable: () => isCloud(),
  },
};

export function getVisibleSidePanelTabs(): SidePanelTabDefinition[] {
  return Object.values(SIDE_PANEL_TABS).filter((tab) => tab.isAvailable());
}
