import type { LighthouseSkillDefinition } from "@/types/lighthouse-skills";

import { LIGHTHOUSE_SKILLS } from "./definitions";

export function getAllSkills(): readonly LighthouseSkillDefinition[] {
  return LIGHTHOUSE_SKILLS;
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
  return nextSkillId ? getSkillById(nextSkillId) : undefined;
}
