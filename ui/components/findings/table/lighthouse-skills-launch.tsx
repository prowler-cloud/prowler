"use client";

import { CornerDownRight } from "lucide-react";

import { LighthouseIcon } from "@/components/icons";
import {
  ActionDropdown,
  ActionDropdownItem,
  DropdownMenuSeparator,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
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
function LighthouseSkillsMenuItems({
  onLaunch,
}: {
  onLaunch: (skill: LighthouseSkillDefinition) => void;
}) {
  return (
    <>
      {getAllSkills().map((skill) => (
        <ActionDropdownItem
          key={skill.id}
          icon={<skill.icon className="text-text-lighthouse" />}
          label={skill.name}
          description={skill.description}
          onSelect={() => onLaunch(skill)}
        />
      ))}
    </>
  );
}

// Shared ⋮-menu wrapper used by both finding-group and resource rows.
export function LighthouseSkillsSubmenu({
  onLaunch,
}: {
  onLaunch: (skill: LighthouseSkillDefinition) => void;
}) {
  return (
    <>
      <DropdownMenuSeparator />
      <DropdownMenuSub>
        <DropdownMenuSubTrigger className="hover:bg-bg-neutral-tertiary flex cursor-pointer items-center gap-2 rounded-md">
          <LighthouseIcon size={16} aria-hidden />
          Lighthouse Skills
        </DropdownMenuSubTrigger>
        <DropdownMenuSubContent
          variant="lighthouse"
          className="bg-bg-neutral-secondary w-72 rounded-xl"
        >
          <LighthouseSkillsMenuItems onLaunch={onLaunch} />
        </DropdownMenuSubContent>
      </DropdownMenuSub>
    </>
  );
}

// Hover swap over the child-row corner arrow (design 1a revisited): at rest
// the ↳ arrow occupies its normal 16px slot, so the row reserves no pill
// width; on row hover, keyboard focus, or while the menu is open, the Skills
// pill overlays the arrow, extending right over the row content. Relies on
// the DataTable row's `group` class.
export function LighthouseSkillsRowButton({
  findingItem,
  onSkillLaunch,
}: {
  findingItem: LighthouseFindingContextItem;
  // Fired on launch so the owning table can open this row's finding detail
  // drawer behind the chat tab.
  onSkillLaunch?: () => void;
}) {
  const launchSkill = useLighthouseSkillLaunch();

  return (
    <span className="relative flex size-4 shrink-0 items-center justify-center">
      <ActionDropdown
        ariaLabel="Lighthouse skills for this finding"
        className="w-72"
        align="start"
        menuVariant="lighthouse"
        trigger={
          <button
            type="button"
            className={cn(
              // Overlay: right edge pinned to the arrow slot, extending left
              // over the dot and the row indent — nothing interactive lives
              // there, so the checkbox next to the arrow stays clickable. The
              // scroll container's pl-6 (padding, inside the clip region)
              // provides the room; a margin there would clip the pill.
              "absolute top-1/2 right-0 z-10 w-16 -translate-y-1/2",
              // Opaque base under the translucent gradient: the pill covers
              // row content, which must not show through. bg-bg-neutral-
              // tertiary matches the hovered row background.
              "border-border-lighthouse bg-bg-neutral-tertiary bg-lighthouse-soft text-text-lighthouse inline-flex items-center justify-center gap-1 rounded-full border py-1 text-xs font-medium",
              "peer opacity-0 transition-opacity group-hover:opacity-100 focus-visible:opacity-100 data-[state=open]:opacity-100",
            )}
          >
            <LighthouseIcon size={14} aria-hidden />
            Skills
          </button>
        }
      >
        <LighthouseSkillsMenuItems
          onLaunch={(skill) => {
            onSkillLaunch?.();
            launchSkill(skill, findingItem);
          }}
        />
      </ActionDropdown>
      {/* peer-*: the arrow hides exactly while the pill shows, including when
          the open menu keeps the pill visible without hover. */}
      <CornerDownRight
        className="text-text-neutral-tertiary h-4 w-4 shrink-0 transition-opacity group-hover:opacity-0 peer-focus-visible:opacity-0 peer-data-[state=open]:opacity-0"
        aria-hidden
      />
    </span>
  );
}
