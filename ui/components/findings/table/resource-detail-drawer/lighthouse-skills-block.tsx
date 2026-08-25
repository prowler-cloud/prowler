"use client";

import { ArrowRight } from "lucide-react";

import { LighthouseIcon } from "@/components/icons";
import { Card } from "@/components/shadcn/card/card";
import { getAllSkills } from "@/lib/lighthouse/skills/registry";
import type { LighthouseSkillDefinition } from "@/types/lighthouse-skills";

interface LighthouseSkillsBlockProps {
  onLaunchSkill: (skill: LighthouseSkillDefinition) => void;
  onAskAnything: () => void;
}

// Finding-detail CTA: a grid of launchable agentic workflows plus
// the free-form "ask anything" fallback that the old gradient banner offered.
export function LighthouseSkillsBlock({
  onLaunchSkill,
  onAskAnything,
}: LighthouseSkillsBlockProps) {
  return (
    <Card variant="lighthouse" className="gap-3 p-4">
      <div className="flex items-center gap-2">
        <LighthouseIcon size={16} />
        <span className="text-text-neutral-primary text-sm font-semibold">
          Lighthouse AI Skills
        </span>
        <span className="text-text-neutral-tertiary ml-auto text-xs">
          Run in chat
        </span>
      </div>
      <div className="grid grid-cols-1 gap-2 @md:grid-cols-2">
        {getAllSkills().map((skill) => (
          <SkillCard
            key={skill.id}
            skill={skill}
            onLaunch={() => onLaunchSkill(skill)}
          />
        ))}
      </div>
      <button
        type="button"
        onClick={onAskAnything}
        className="text-text-lighthouse self-end text-xs underline-offset-2 hover:underline"
      >
        Or ask Lighthouse anything about this finding →
      </button>
    </Card>
  );
}

function SkillCard({
  skill,
  onLaunch,
}: {
  skill: LighthouseSkillDefinition;
  onLaunch: () => void;
}) {
  const Icon = skill.icon;

  return (
    <button
      type="button"
      onClick={onLaunch}
      disabled={!skill.enabled}
      className="group border-border-neutral-secondary bg-bg-neutral-secondary hover:bg-bg-neutral-tertiary disabled:hover:bg-bg-neutral-secondary flex items-start gap-2.5 rounded-lg border p-3 text-left transition-colors disabled:cursor-not-allowed disabled:opacity-60"
    >
      <Icon
        className="text-text-lighthouse mt-0.5 size-4 shrink-0"
        aria-hidden
      />
      <span className="flex min-w-0 flex-col gap-0.5">
        <span className="text-text-neutral-primary flex items-center gap-1.5 text-sm font-medium">
          {skill.name}
          {skill.enabled ? (
            <ArrowRight
              className="text-text-lighthouse size-3.5 opacity-0 transition-opacity group-hover:opacity-100"
              aria-hidden
            />
          ) : (
            <span className="text-text-neutral-tertiary text-xs font-normal">
              Coming soon
            </span>
          )}
        </span>
        <span className="text-text-neutral-secondary text-xs leading-snug">
          {skill.description}
        </span>
      </span>
    </button>
  );
}
