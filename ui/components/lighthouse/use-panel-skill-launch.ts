"use client";

import { SIDE_PANEL_TAB, useSidePanelStore } from "@/store/side-panel";
import type { LighthouseContextEnvelope } from "@/types/lighthouse-context";
import type { LighthouseSkillDefinition } from "@/types/lighthouse-skills";

// Opens the Lighthouse AI tab and runs the skill there as a fresh chat.
export function usePanelSkillLaunch() {
  const openSidePanel = useSidePanelStore((state) => state.openPanel);

  return (
    skill: LighthouseSkillDefinition,
    context: LighthouseContextEnvelope,
  ) => {
    openSidePanel(SIDE_PANEL_TAB.AI_CHAT);
    // Lazy import: the panel chat store pulls in the whole chat/server-action
    // graph, which launch surfaces must not load just to render. Ordering is
    // safe — the store queues launches until the panel exists.
    void import("@/app/(prowler)/lighthouse/_lib/panel-chat-store").then(
      ({ requestPanelSkillLaunch }) => requestPanelSkillLaunch(skill, context),
    );
  };
}
