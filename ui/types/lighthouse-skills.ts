import type { LucideIcon } from "lucide-react";

// Persisted reference stored in a user message part's `ui_skill` content field.
// It is what lets the UI render the skill card after a reload, so it carries
// the display name and version alongside the id.
export interface LighthouseSkillRef {
  skillId: string;
  name: string;
  version: number;
}

export interface LighthouseSkillDefinition {
  id: string;
  name: string;
  description: string;
  icon: LucideIcon;
  // Ordered workflow steps. The instructions tell the model to announce each
  // one with a [[step:n]] marker, which drives the progress UI.
  steps: string[];
  // Skill-specific guidance appended to the shared step protocol.
  guidance: string;
  // Suggested follow-up skill shown on the completed state ("Next: ... →").
  nextSkillId: string | null;
  version: number;
}
