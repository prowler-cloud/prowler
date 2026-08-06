import {
  type ApiLighthouseContextEnvelope,
  buildAgentText,
} from "@/lib/lighthouse/context/transport";
import type {
  LighthouseSkillDefinition,
  LighthouseSkillRef,
} from "@/types/lighthouse-skills";

// Mirrors the [PROWLER_UI_CONTEXT_V1] transport: the skill instructions ride
// inside the agent-facing `text` while the UI only ever renders
// `display_text`/`ui_skill`, so the prompt stays invisible to the user.
const SKILL_BLOCK_START = "[PROWLER_UI_SKILL_V1]";
const SKILL_BLOCK_END = "[/PROWLER_UI_SKILL_V1]";

const SKILL_PREAMBLE =
  "The user launched this Lighthouse skill from the Prowler UI. Treat the instructions below as the task for this turn.";

// Unlike the context block (untrusted data), this block IS the instruction set
// for the turn — which is exactly why the two travel in separate sentinels.
export interface ApiLighthouseSkillRef {
  skill_id: string;
  name: string;
  version: number;
}

export function toApiSkillRef(
  skill: LighthouseSkillDefinition,
): ApiLighthouseSkillRef {
  return { skill_id: skill.id, name: skill.name, version: skill.version };
}

export function fromApiSkillRef(
  value: unknown,
): LighthouseSkillRef | undefined {
  if (typeof value !== "object" || value === null) return undefined;
  const record = value as Record<string, unknown>;
  if (
    typeof record.skill_id !== "string" ||
    typeof record.name !== "string" ||
    typeof record.version !== "number"
  ) {
    return undefined;
  }
  return {
    skillId: record.skill_id,
    name: record.name,
    version: record.version,
  };
}

export function buildSkillAgentText(
  displayText: string,
  skill: LighthouseSkillDefinition,
  apiContext?: ApiLighthouseContextEnvelope,
): string {
  const body = apiContext
    ? buildAgentText(displayText, apiContext)
    : displayText;

  return [
    SKILL_BLOCK_START,
    serializeSkillRef(toApiSkillRef(skill)),
    SKILL_PREAMBLE,
    escapeSkillSentinels(buildSkillInstructions(skill)),
    SKILL_BLOCK_END,
    "",
    body,
  ].join("\n");
}

// No step plan: the agent decides its own flow, and the UI derives progress
// from real stream events (tool calls, narration).
function buildSkillInstructions(skill: LighthouseSkillDefinition): string {
  return [
    `Skill: ${skill.name} — ${skill.description}.`,
    "Guidelines:",
    "- Narrate what you are doing in one short sentence as you move through the work.",
    "- Use the available tools to gather real evidence; never fabricate data.",
    "- Finish by producing the complete answer in markdown.",
    skill.guidance,
  ].join("\n");
}

function serializeSkillRef(ref: ApiLighthouseSkillRef): string {
  return escapeSkillSentinels(
    JSON.stringify(
      Object.fromEntries(
        Object.entries(ref).sort(([left], [right]) =>
          left.localeCompare(right),
        ),
      ),
    ),
  );
}

function escapeSkillSentinels(value: string): string {
  return value
    .replaceAll(SKILL_BLOCK_START, `\\u005B${SKILL_BLOCK_START.slice(1)}`)
    .replaceAll(SKILL_BLOCK_END, `\\u005B${SKILL_BLOCK_END.slice(1)}`);
}
