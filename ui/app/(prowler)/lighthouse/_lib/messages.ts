import {
  LIGHTHOUSE_V2_PART_TYPE,
  type LighthouseV2Message,
  type LighthouseV2MessageRole,
} from "@/app/(prowler)/lighthouse/_types";

// Message parts can arrive as a raw string or as a `{ text }` object; this
// normalizes both to a plain string and ignores anything else.
export function getTextContent(content: unknown): string {
  if (typeof content === "string") {
    return content;
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

// Builds a client-only message shown immediately after submit, before the
// backend echoes the persisted message back through the stream/refresh.
export function buildOptimisticMessage(
  role: LighthouseV2MessageRole,
  text: string,
): LighthouseV2Message {
  const now = new Date().toISOString();
  const id = `optimistic-${role}-${now}`;
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
        content: { text },
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
