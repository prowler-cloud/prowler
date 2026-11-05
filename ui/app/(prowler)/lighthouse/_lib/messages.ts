import {
  LIGHTHOUSE_V2_MESSAGE_ROLE,
  LIGHTHOUSE_V2_PART_TYPE,
  type LighthouseV2Message,
  type LighthouseV2MessageRole,
} from "@/app/(prowler)/lighthouse/_types";
import { fromApiLighthouseContext } from "@/lib/lighthouse/context/transport";
import { buildLighthouseMessageContent } from "@/lib/lighthouse/message-content";
import { fromApiSkillRef } from "@/lib/lighthouse/skills/transport";
import type { LighthouseContextEnvelope } from "@/types/lighthouse-context";
import type {
  LighthouseSkillDefinition,
  LighthouseSkillRef,
} from "@/types/lighthouse-skills";

// Message parts can arrive as a raw string or as a `{ text }` object; this
// normalizes both to a plain string and ignores anything else.
export function getTextContent(content: unknown): string {
  if (typeof content === "string") {
    return content;
  }
  if (
    typeof content === "object" &&
    content !== null &&
    "display_text" in content &&
    typeof content.display_text === "string"
  ) {
    return content.display_text;
  }
  if (
    typeof content === "object" &&
    content !== null &&
    "text" in content &&
    typeof content.text === "string"
  ) {
    return content.text;
  }
  return "";
}

export function getLighthouseContext(
  content: unknown,
): LighthouseContextEnvelope | undefined {
  if (
    typeof content !== "object" ||
    content === null ||
    !("ui_context" in content)
  ) {
    return undefined;
  }
  return fromApiLighthouseContext(content.ui_context);
}

// Reads the persisted skill reference back out of a user message part so the
// skill card survives reloads and history without parsing the prompt text.
export function getSkillRef(content: unknown): LighthouseSkillRef | undefined {
  if (
    typeof content !== "object" ||
    content === null ||
    !("ui_skill" in content)
  ) {
    return undefined;
  }
  return fromApiSkillRef(content.ui_skill);
}

// The user launch an assistant message responded to.
export interface SkillRunInfo {
  ref: LighthouseSkillRef;
  context?: LighthouseContextEnvelope;
  launchedAt: string;
}

// An assistant message is a "skill response" when the user turn right before
// it launched a skill; the persisted ui_skill/ui_context on that turn feed the
// receipt and the action row.
export function getSkillRunFromLaunch(
  message: LighthouseV2Message,
  previous: LighthouseV2Message | undefined,
): SkillRunInfo | undefined {
  if (
    message.role !== LIGHTHOUSE_V2_MESSAGE_ROLE.ASSISTANT ||
    previous?.role !== LIGHTHOUSE_V2_MESSAGE_ROLE.USER
  ) {
    return undefined;
  }
  const textParts = previous.parts.filter(
    (part) => part.type === LIGHTHOUSE_V2_PART_TYPE.TEXT,
  );
  const ref = textParts
    .map((part) => getSkillRef(part.content))
    .find((skillRef) => skillRef !== undefined);
  if (!ref) return undefined;

  const context = textParts
    .map((part) => getLighthouseContext(part.content))
    .find((value) => value !== undefined);
  return {
    ref,
    ...(context ? { context } : {}),
    launchedAt: previous.insertedAt,
  };
}

// Monotonic counter guaranteeing unique optimistic ids even when two messages
// are built within the same millisecond (toISOString alone is ms-granular).
let optimisticMessageCounter = 0;

// Builds a client-only message shown immediately after submit, before the
// backend echoes the persisted message back through the stream/refresh.
export function buildOptimisticMessage(
  role: LighthouseV2MessageRole,
  displayText: string,
  context?: LighthouseContextEnvelope,
  skill?: LighthouseSkillDefinition,
): LighthouseV2Message {
  const now = new Date().toISOString();
  optimisticMessageCounter += 1;
  const id = `optimistic-${role}-${now}-${optimisticMessageCounter}`;
  return {
    id,
    role,
    model: null,
    tokenUsage: null,
    insertedAt: now,
    parts: [
      {
        id: `${id}-part`,
        type: LIGHTHOUSE_V2_PART_TYPE.TEXT,
        content: buildLighthouseMessageContent(displayText, context, skill),
        toolCallOutcome: null,
        insertedAt: now,
        updatedAt: now,
      },
    ],
  };
}

// Derives a session title from the first user message (collapsed + truncated).
export function buildSessionTitle(text: string): string {
  const normalized = text.replace(/\s+/g, " ").trim();
  return normalized.length > 80 ? `${normalized.slice(0, 77)}...` : normalized;
}
