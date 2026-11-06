"use client";

import { ChevronDown } from "lucide-react";

import { LighthouseSkillsMenuItems } from "@/components/findings/table/lighthouse-skills-launch";
import { LighthouseIcon } from "@/components/icons";
import { ActionDropdown } from "@/components/shadcn/dropdown";
import {
  getLaunchableSkills,
  getSkillsForSurface,
} from "@/lib/lighthouse/skills/registry";
import {
  LIGHTHOUSE_SKILL_SURFACE,
  type LighthouseSkillDefinition,
  type LighthouseSkillSurface,
} from "@/types/lighthouse-skills";

interface LighthouseSkillsRailProps {
  // Which catalog the rail offers: a finding's skills or an issue's.
  surface?: LighthouseSkillSurface;
  onLaunchSkill: (skill: LighthouseSkillDefinition) => void;
  // Free-text prompt submitted from the menu footer; starts a fresh
  // Lighthouse panel conversation with the typed text.
  onSubmitPrompt: (text: string) => void;
}

// Finding-detail skill launcher (chip rail): one compact row under the
// finding title — direct-launch chips plus a +N trigger opening the same
// skills menu used by the table row surfaces.
export function LighthouseSkillsRail({
  surface = LIGHTHOUSE_SKILL_SURFACE.FINDING,
  onLaunchSkill,
  onSubmitPrompt,
}: LighthouseSkillsRailProps) {
  // Launchable skills become direct-launch chips; +N counts what the rail
  // hides (disabled skills today). The menu is the app-wide skills menu.
  const chipSkills = getLaunchableSkills(surface);
  const overflowCount = getSkillsForSurface(surface).length - chipSkills.length;
  return (
    <div className="border-border-lighthouse bg-lighthouse-soft flex h-10 shrink-0 items-center gap-2 rounded-xl border px-3">
      <div className="flex shrink-0 items-center gap-1.5">
        <LighthouseIcon size={16} aria-hidden />
        <span className="text-text-neutral-primary text-sm font-semibold">
          Skills
        </span>
      </div>
      <span aria-hidden className="bg-border-lighthouse h-5 w-px shrink-0" />
      <div className="no-scrollbar flex min-w-0 flex-1 items-center gap-2 overflow-x-auto">
        {chipSkills.map((skill) => (
          <button
            key={skill.id}
            type="button"
            onClick={() => onLaunchSkill(skill)}
            className="border-border-lighthouse text-text-neutral-primary hover:bg-bg-neutral-tertiary inline-flex shrink-0 cursor-pointer items-center gap-1.5 rounded-full border px-3 py-1 text-sm font-medium transition-colors"
          >
            <skill.icon className="text-text-lighthouse size-3.5" aria-hidden />
            {skill.name}
          </button>
        ))}
      </div>
      <span aria-hidden className="bg-border-lighthouse h-5 w-px shrink-0" />
      {/* Pinned outside the scroll strip so the trigger never scrolls away. */}
      <ActionDropdown
        align="end"
        menuVariant="lighthouse"
        className="bg-bg-neutral-secondary w-80 rounded-xl"
        ariaLabel="More Lighthouse skills"
        trigger={
          <button
            type="button"
            aria-label="More Lighthouse skills"
            className="text-text-lighthouse inline-flex shrink-0 cursor-pointer items-center gap-1 text-sm font-medium"
          >
            {overflowCount > 0 && `+${overflowCount}`}
            <ChevronDown className="size-4" aria-hidden />
          </button>
        }
      >
        <LighthouseSkillsMenuItems
          surface={surface}
          onLaunch={onLaunchSkill}
          onSubmitPrompt={onSubmitPrompt}
        />
      </ActionDropdown>
    </div>
  );
}
