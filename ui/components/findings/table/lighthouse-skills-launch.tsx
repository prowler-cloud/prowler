"use client";

import { Sparkles } from "lucide-react";

import {
  ActionDropdown,
  ActionDropdownItem,
} from "@/components/shadcn/dropdown";
import { getAllSkills } from "@/lib/lighthouse/skills/registry";
import { cn } from "@/lib/utils";
import { SIDE_PANEL_TAB, useSidePanelStore } from "@/store/side-panel";
import {
  LIGHTHOUSE_CONTEXT_TRANSPORT,
  type LighthouseFindingContextItem,
} from "@/types/lighthouse-context";
import type { LighthouseSkillDefinition } from "@/types/lighthouse-skills";

// Launching from a table row bypasses the context-contribution store: the row
// already knows its finding, so the launch carries a minimal one-item envelope.
export function useLighthouseSkillLaunch() {
  const openSidePanel = useSidePanelStore((state) => state.openPanel);

  return (
    skill: LighthouseSkillDefinition,
    findingItem: LighthouseFindingContextItem,
  ) => {
    openSidePanel(SIDE_PANEL_TAB.AI_CHAT);
    // Lazy import: the panel chat store pulls in the whole chat/server-action
    // graph, which table columns must not load just to render a menu. Ordering
    // is safe — the store queues launches until the panel exists.
    void import("@/app/(prowler)/lighthouse/_lib/panel-chat-store").then(
      ({ requestPanelSkillLaunch }) =>
        requestPanelSkillLaunch(skill, {
          schemaVersion: 1,
          transport: LIGHTHOUSE_CONTEXT_TRANSPORT.INLINE,
          items: [findingItem],
        }),
    );
  };
}

// Shared menu body for the row ⋮ submenu (design 1c) and the hover pill
// (design 1a) — one skill per item, description underneath.
export function LighthouseSkillsMenuItems({
  onLaunch,
}: {
  onLaunch: (skill: LighthouseSkillDefinition) => void;
}) {
  return (
    <>
      {getAllSkills().map((skill) => (
        <ActionDropdownItem
          key={skill.id}
          icon={<skill.icon className="text-text-success-primary" />}
          label={skill.name}
          description={skill.description}
          onSelect={() => onLaunch(skill)}
        />
      ))}
    </>
  );
}

// Hover-revealed "Skills" pill on resource sub-rows (design 1a). Relies on the
// DataTable row's `group` class: invisible at rest, revealed on row hover,
// keyboard focus, or while its menu is open.
export function LighthouseSkillsRowButton({
  findingItem,
}: {
  findingItem: LighthouseFindingContextItem;
}) {
  const launchSkill = useLighthouseSkillLaunch();

  return (
    <ActionDropdown
      ariaLabel="Lighthouse skills for this finding"
      className="w-72"
      trigger={
        <button
          type="button"
          className={cn(
            "border-border-neutral-secondary bg-bg-pass-secondary text-text-success-primary inline-flex shrink-0 items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium",
            "opacity-0 transition-opacity group-hover:opacity-100 focus-visible:opacity-100 data-[state=open]:opacity-100",
          )}
        >
          <Sparkles className="size-3.5" aria-hidden />
          Skills
        </button>
      }
    >
      <LighthouseSkillsMenuItems
        onLaunch={(skill) => launchSkill(skill, findingItem)}
      />
    </ActionDropdown>
  );
}
