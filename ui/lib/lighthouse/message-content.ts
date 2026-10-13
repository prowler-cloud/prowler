import {
  buildAgentText,
  toApiLighthouseContext,
} from "@/lib/lighthouse/context/transport";
import {
  buildSkillAgentText,
  toApiSkillRef,
} from "@/lib/lighthouse/skills/transport";
import type { LighthouseContextEnvelope } from "@/types/lighthouse-context";
import type { LighthouseSkillDefinition } from "@/types/lighthouse-skills";

// Single builder for a user message part's `content`, shared by the optimistic
// client message and the API payload so the two can never drift. The backend
// persists this blob opaquely: `text` is what the agent reads, the rest exists
// purely for the UI to render the message back.
export function buildLighthouseMessageContent(
  displayText: string,
  context?: LighthouseContextEnvelope,
  skill?: LighthouseSkillDefinition,
) {
  const apiContext = context ? toApiLighthouseContext(context) : undefined;

  if (skill) {
    return {
      text: buildSkillAgentText(displayText, skill, apiContext),
      display_text: displayText,
      ...(apiContext ? { ui_context: apiContext } : {}),
      ui_skill: toApiSkillRef(skill),
    };
  }

  if (apiContext) {
    return {
      text: buildAgentText(displayText, apiContext),
      display_text: displayText,
      ui_context: apiContext,
    };
  }

  return { text: displayText };
}
