import { Badge } from "@/components/shadcn/badge/badge";
import type { LighthouseSkillDefinition } from "@/types/lighthouse-skills";

// Composer pill (design 1e): pinned next to the context chip while a skill run
// is live. Purely informative — there is no cancel/stop yet.
export function SkillComposerPill({
  skill,
}: {
  skill: LighthouseSkillDefinition;
}) {
  return (
    <Badge variant="lighthouse" role="status" className="max-w-56">
      <span
        className="bg-text-lighthouse size-1.5 shrink-0 animate-pulse rounded-full"
        aria-hidden
      />
      <span className="truncate">Skill · {skill.name}</span>
    </Badge>
  );
}
