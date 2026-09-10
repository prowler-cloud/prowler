import "server-only";

import type { SkillDefinition, SkillMetadata } from "./types";

const skillRegistry = new Map<string, SkillDefinition>();

export function registerSkill(skill: SkillDefinition): void {
  skillRegistry.set(skill.metadata.id, skill);
}

export function getAllSkillMetadata(): SkillMetadata[] {
  return Array.from(skillRegistry.values()).map((skill) => skill.metadata);
}

export function getSkillById(id: string): SkillDefinition | undefined {
  return skillRegistry.get(id);
}

export function getRegisteredSkillIds(): string[] {
  return Array.from(skillRegistry.keys());
}
