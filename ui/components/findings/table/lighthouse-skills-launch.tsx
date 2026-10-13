"use client";

import { CornerDownRight, PencilLine } from "lucide-react";
import { useState, type KeyboardEvent } from "react";

import { LighthouseIcon } from "@/components/icons";
import {
  ActionDropdown,
  ActionDropdownItem,
  DropdownMenuLabel,
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
  type LighthouseContextEnvelope,
  type LighthouseFindingContextItem,
} from "@/types/lighthouse-context";
import type { LighthouseSkillDefinition } from "@/types/lighthouse-skills";

// Launching from a table row bypasses the context-contribution store: the row
// already knows its finding, so the launch carries a minimal one-item envelope.
function buildRowEnvelope(
  findingItem: LighthouseFindingContextItem,
): LighthouseContextEnvelope {
  return {
    schemaVersion: 1,
    transport: LIGHTHOUSE_CONTEXT_TRANSPORT.INLINE,
    items: [findingItem],
  };
}

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
        requestPanelSkillLaunch(skill, buildRowEnvelope(findingItem)),
    );
  };
}

// Free-text sibling of useLighthouseSkillLaunch: starts a fresh Lighthouse
// conversation about the row's finding with whatever the user typed.
export function useLighthousePromptLaunch() {
  const openSidePanel = useSidePanelStore((state) => state.openPanel);

  return (text: string, findingItem: LighthouseFindingContextItem) => {
    openSidePanel(SIDE_PANEL_TAB.AI_CHAT);
    void import("@/app/(prowler)/lighthouse/_lib/panel-chat-store").then(
      ({ requestPanelChatMessage }) =>
        requestPanelChatMessage(text, buildRowEnvelope(findingItem)),
    );
  };
}

// The one skills-menu catalog split, shared by every surface: the first
// enabled skill leads as RECOMMENDED, the rest follow in catalog order.
const MENU_SKILLS = getAllSkills();
const RECOMMENDED_SKILL = MENU_SKILLS.find((skill) => skill.enabled);
const REST_SKILLS = MENU_SKILLS.filter((skill) => skill !== RECOMMENDED_SKILL);

// THE Lighthouse skills menu. Every surface that opens a skills dropdown
// (row ⋮ submenu, hover pill, finding-detail rail) must render this body so
// the menu stays identical app-wide. `onSubmitPrompt` adds the free-text
// "Ask Lighthouse anything..." footer.
export function LighthouseSkillsMenuItems({
  onLaunch,
  onSubmitPrompt,
}: {
  onLaunch: (skill: LighthouseSkillDefinition) => void;
  onSubmitPrompt?: (text: string) => void;
}) {
  return (
    <>
      {RECOMMENDED_SKILL && (
        <>
          <DropdownMenuLabel className="text-text-neutral-tertiary text-[10px] font-semibold tracking-wider uppercase">
            Recommended
          </DropdownMenuLabel>
          <ActionDropdownItem
            icon={<RECOMMENDED_SKILL.icon className="text-text-lighthouse" />}
            label={RECOMMENDED_SKILL.name}
            description={RECOMMENDED_SKILL.description}
            className="bg-bg-neutral-tertiary"
            onSelect={() => onLaunch(RECOMMENDED_SKILL)}
          />
          <DropdownMenuSeparator />
        </>
      )}
      {REST_SKILLS.map((skill) => (
        <ActionDropdownItem
          key={skill.id}
          icon={<skill.icon className="text-text-lighthouse" />}
          label={skill.name}
          description={skill.description}
          disabled={!skill.enabled}
          disabledTooltip="Coming soon"
          onSelect={() => onLaunch(skill)}
        />
      ))}
      {onSubmitPrompt && (
        <>
          <DropdownMenuSeparator />
          <AskLighthouseAnythingRow onSubmit={onSubmitPrompt} />
        </>
      )}
    </>
  );
}

// Plain div on purpose: a DropdownMenuItem would hand the row to Radix roving
// focus and close the menu on select while the user is still typing.
function AskLighthouseAnythingRow({
  onSubmit,
}: {
  onSubmit: (text: string) => void;
}) {
  // Local state needed: the prompt is buffered until the user submits.
  const [prompt, setPrompt] = useState("");

  const handleKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    // Let Escape bubble so Radix closes the menu as usual.
    if (event.key === "Escape") return;
    // Keep every other key away from the menu: Radix typeahead would steal
    // printable characters to focus items while the user is typing.
    event.stopPropagation();
    if (event.key !== "Enter") return;
    event.preventDefault();
    const text = prompt.trim();
    if (!text) return;
    onSubmit(text);
    setPrompt("");
    // Close the whole menu tree (works from submenus too) by replaying the
    // native dismissal path instead of threading open-state through props.
    event.currentTarget.dispatchEvent(
      new KeyboardEvent("keydown", { key: "Escape", bubbles: true }),
    );
  };

  return (
    <div className="flex items-center gap-2 px-2 py-1.5">
      <PencilLine
        className="text-text-neutral-tertiary size-4 shrink-0"
        aria-hidden
      />
      <input
        type="text"
        aria-label="Ask Lighthouse anything"
        placeholder="Ask Lighthouse anything..."
        value={prompt}
        onChange={(event) => setPrompt(event.target.value)}
        onKeyDown={handleKeyDown}
        className="text-text-neutral-primary placeholder:text-text-neutral-tertiary min-w-0 flex-1 bg-transparent text-sm outline-none"
      />
    </div>
  );
}

// Shared ⋮-menu wrapper used by both finding-group and resource rows.
export function LighthouseSkillsSubmenu({
  onLaunch,
  onSubmitPrompt,
}: {
  onLaunch: (skill: LighthouseSkillDefinition) => void;
  onSubmitPrompt?: (text: string) => void;
}) {
  return (
    <>
      <DropdownMenuSeparator />
      <DropdownMenuSub>
        <DropdownMenuSubTrigger className="hover:bg-border-neutral-secondary flex cursor-pointer items-center gap-2 rounded-lg">
          <LighthouseIcon size={16} aria-hidden />
          Lighthouse Skills
        </DropdownMenuSubTrigger>
        <DropdownMenuSubContent
          variant="lighthouse"
          className="bg-bg-neutral-secondary w-72 rounded-xl"
        >
          <LighthouseSkillsMenuItems
            onLaunch={onLaunch}
            onSubmitPrompt={onSubmitPrompt}
          />
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
  const launchPrompt = useLighthousePromptLaunch();

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
          onSubmitPrompt={(text) => {
            onSkillLaunch?.();
            launchPrompt(text, findingItem);
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
