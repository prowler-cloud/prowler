import type { LighthouseSkillDefinition } from "@/types/lighthouse-skills";

import { LIGHTHOUSE_SKILLS } from "./definitions";

export function getAllSkills(): readonly LighthouseSkillDefinition[] {
  return LIGHTHOUSE_SKILLS;
}

// Launch surfaces (cards, row menus) render disabled skills as "coming soon"
// but only these can actually start a run.
export function getLaunchableSkills(): readonly LighthouseSkillDefinition[] {
  return LIGHTHOUSE_SKILLS.filter((skill) => skill.enabled);
}

export function getSkillById(
  id: string,
): LighthouseSkillDefinition | undefined {
  return LIGHTHOUSE_SKILLS.find((skill) => skill.id === id);
}

export function getNextSkill(
  id: string,
): LighthouseSkillDefinition | undefined {
  const nextSkillId = getSkillById(id)?.nextSkillId;
  const nextSkill = nextSkillId ? getSkillById(nextSkillId) : undefined;
  return nextSkill?.enabled ? nextSkill : undefined;
}
