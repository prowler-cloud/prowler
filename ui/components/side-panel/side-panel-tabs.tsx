"use client";

import { type ComponentType, lazy, type LazyExoticComponent } from "react";

import { LighthouseIcon } from "@/components/icons";
import { isCloud } from "@/lib/shared/env";
import { SIDE_PANEL_TAB, type SidePanelTabId } from "@/store/side-panel";

interface SidePanelTabDefinition {
  id: SidePanelTabId;
  label: string;
  Icon: ComponentType<{ className?: string }>;
  // Lazy so a tab's bundle (the chat is a heavy one) loads on first open, not
  // on every page.
  Content: LazyExoticComponent<ComponentType>;
  isAvailable: () => boolean;
}

export const SIDE_PANEL_TABS: Record<SidePanelTabId, SidePanelTabDefinition> = {
  [SIDE_PANEL_TAB.AI_CHAT]: {
    id: SIDE_PANEL_TAB.AI_CHAT,
    label: "Lighthouse AI",
    Icon: LighthouseIcon,
    Content: lazy(() =>
      import(
        "@/app/(prowler)/lighthouse/_components/panel/lighthouse-panel-chat"
      ).then((module) => ({ default: module.LighthousePanelChat })),
    ),
    isAvailable: () => isCloud(),
  },
};

export function getVisibleSidePanelTabs(): SidePanelTabDefinition[] {
  return Object.values(SIDE_PANEL_TABS).filter((tab) => tab.isAvailable());
}
