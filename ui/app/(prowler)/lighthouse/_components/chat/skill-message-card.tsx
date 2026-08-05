import { Sparkles } from "lucide-react";

import { getSkillById } from "@/lib/lighthouse/skills/registry";
import {
  LIGHTHOUSE_CONTEXT_KIND,
  type LighthouseContextEnvelope,
} from "@/types/lighthouse-context";
import type { LighthouseSkillRef } from "@/types/lighthouse-skills";

interface SkillMessageCardProps {
  skillRef: LighthouseSkillRef;
  context?: LighthouseContextEnvelope;
}

// A skill launch rendered as the user turn (design 1f): the persisted ui_skill
// ref drives the card, so the hidden prompt never surfaces — not live, not
// after a reload. Falls back to the ref's own name for retired skill ids.
export function SkillMessageCard({ skillRef, context }: SkillMessageCardProps) {
  const definition = getSkillById(skillRef.skillId);
  const Icon = definition?.icon ?? Sparkles;
  const findingLabel = context?.items.find(
    (item) => item.kind === LIGHTHOUSE_CONTEXT_KIND.FINDING,
  )?.label;

  return (
    <div className="bg-lighthouse max-w-full rounded-lg p-px">
      <div className="bg-bg-neutral-primary flex min-w-0 flex-col gap-1 rounded-[7px] px-3.5 py-2.5">
        <span className="flex items-center gap-2">
          <Icon className="text-text-lighthouse size-4 shrink-0" aria-hidden />
          <span className="text-text-lighthouse text-[10px] font-semibold tracking-widest uppercase">
            Skill
          </span>
          <span className="text-text-neutral-primary truncate text-sm font-medium">
            {skillRef.name}
          </span>
        </span>
        {findingLabel && (
          <span className="text-text-neutral-secondary truncate text-xs">
            {findingLabel}
          </span>
        )}
      </div>
    </div>
  );
}
