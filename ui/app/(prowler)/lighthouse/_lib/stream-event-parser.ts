import {
  LIGHTHOUSE_V2_SSE_EVENT,
  type LighthouseV2SSEEvent,
} from "@/app/(prowler)/lighthouse/_types";

// Parses a raw browser SSE event into a typed Lighthouse v2 stream event.
// The backend sends one named event per SSE type; the data payload is JSON.
export function parseStreamEvent(
  event: Event,
  type: LighthouseV2SSEEvent["type"],
): LighthouseV2SSEEvent {
  const data = event instanceof MessageEvent ? parseJsonObject(event.data) : {};

  if (type === LIGHTHOUSE_V2_SSE_EVENT.MESSAGE_DELTA) {
    return {
      type,
      content: readString(data, "content"),
    };
  }
  if (type === LIGHTHOUSE_V2_SSE_EVENT.TOOL_CALL_START) {
    return {
      type,
      toolCallId: readString(data, "tool_call_id"),
      toolName: readString(data, "tool_name"),
    };
  }
  if (type === LIGHTHOUSE_V2_SSE_EVENT.TOOL_CALL_END) {
    return {
      type,
      toolCallId: readString(data, "tool_call_id"),
      outcome: readString(data, "outcome"),
    };
  }
  if (type === LIGHTHOUSE_V2_SSE_EVENT.MESSAGE_END) {
    return {
      type,
      messageId: readString(data, "message_id"),
    };
  }
  return {
    type: LIGHTHOUSE_V2_SSE_EVENT.ERROR,
    code: readString(data, "code"),
    detail: readString(data, "detail"),
  };
}

function parseJsonObject(value: unknown): Record<string, unknown> {
  if (typeof value !== "string") {
    return {};
  }
  try {
    const parsed: unknown = JSON.parse(value);
    return typeof parsed === "object" && parsed !== null
      ? (parsed as Record<string, unknown>)
      : {};
  } catch {
    return {};
  }
}

function readString(data: Record<string, unknown>, key: string): string {
  const value = data[key];
  return typeof value === "string" ? value : "";
}
