import type { LucideIcon } from "lucide-react";

// PostHog multivariate flag deciding which skill launcher the finding detail
// drawer renders. Anything other than "dropdown" falls back to the card control.
export const SKILL_LAUNCHER_FLAG = "finding-detail-skill-launcher";

export const SKILL_LAUNCHER_VARIANT = {
  CARD: "card",
  DROPDOWN: "dropdown",
} as const;

export type SkillLauncherVariant =
  (typeof SKILL_LAUNCHER_VARIANT)[keyof typeof SKILL_LAUNCHER_VARIANT];

export const LIGHTHOUSE_SKILL_ID = {
  CONTEXTUAL_FIX: "contextual-fix",
  TRIAGE_DECISION: "triage-decision",
  SYSTEMIC_SCOPE: "systemic-scope",
  COMPLIANCE_IMPACT: "compliance-impact",
} as const;

export type LighthouseSkillId =
  (typeof LIGHTHOUSE_SKILL_ID)[keyof typeof LIGHTHOUSE_SKILL_ID];

// Persisted reference stored in a user message part's `ui_skill` content field.
// It is what lets the UI render the skill card after a reload, so it carries
// the display name and version alongside the id.
export interface LighthouseSkillRef {
  skillId: string;
  name: string;
  version: number;
}

export interface LighthouseSkillDefinition {
  id: LighthouseSkillId;
  name: string;
  description: string;
  icon: LucideIcon;
  // Full self-contained prompt authored by the DyR team: tool loading, step
  // order and report shape. There is no step plan protocol: the agent decides
  // its own flow, and the UI reports progress from real stream events.
  prompt: string;
  // Suggested follow-up skill shown on the completed state ("Next: ... →").
  nextSkillId: LighthouseSkillId | null;
  // Disabled skills render as "coming soon" and cannot be launched (e.g.
  // Compliance Impact, whose prompt is blocked on a missing MCP tool).
  enabled: boolean;
  version: number;
}
