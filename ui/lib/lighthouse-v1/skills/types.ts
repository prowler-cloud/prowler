export interface SkillMetadata {
  id: string;
  name: string;
  description: string;
}

export interface SkillDefinition {
  metadata: SkillMetadata;
  instructions: string;
}
