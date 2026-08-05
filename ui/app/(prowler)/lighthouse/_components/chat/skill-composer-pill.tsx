"use client";

import type { LighthouseSkillDefinition } from "@/types/lighthouse-skills";

// Composer pill (design 1e): pinned next to the context chip while a skill run
// is live. Purely informative — there is no cancel/stop yet.
export function SkillComposerPill({
  skill,
}: {
  skill: LighthouseSkillDefinition;
}) {
  return (
    <span
      role="status"
      className="border-border-neutral-secondary bg-bg-pass-secondary text-text-success-primary inline-flex max-w-56 shrink-0 items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium"
    >
      <span
        className="bg-bg-pass-primary size-1.5 shrink-0 animate-pulse rounded-full"
        aria-hidden
      />
      <span className="truncate">Skill · {skill.name}</span>
    </span>
  );
}
