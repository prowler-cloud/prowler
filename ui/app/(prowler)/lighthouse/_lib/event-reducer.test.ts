import { describe, expect, it } from "vitest";

import {
  createInitialLighthouseV2StreamState,
  reduceLighthouseV2Event,
} from "./event-reducer";

describe("event-reducer", () => {
  it("should append message deltas", () => {
    // Given
    const state = createInitialLighthouseV2StreamState("task-1");

    // When
    const next = reduceLighthouseV2Event(state, {
      type: "message.delta",
      content: "Hello",
    });

    // Then
    expect(next.assistantText).toBe("Hello");
    expect(next.status).toBe("streaming");
  });

  it("should pair tool start and end events", () => {
    // Given
    const state = reduceLighthouseV2Event(
      createInitialLighthouseV2StreamState("task-1"),
      {
        type: "tool_call.start",
        toolCallId: "tool-1",
        toolName: "search",
      },
    );

    // When
    const next = reduceLighthouseV2Event(state, {
      type: "tool_call.end",
      toolCallId: "tool-1",
      outcome: "success",
    });

    // Then
    expect(next.toolCalls).toEqual([
      {
        id: "tool-1",
        name: "search",
        status: "completed",
        outcome: "success",
      },
    ]);
  });

  it("should preserve the live display order of text and tool events", () => {
    // Given
    let state = createInitialLighthouseV2StreamState("task-1");

    // When
    state = reduceLighthouseV2Event(state, {
      type: "message.delta",
      content: "Voy a buscar los findings por severidad",
    });
    state = reduceLighthouseV2Event(state, {
      type: "tool_call.start",
      toolCallId: "tool-1",
      toolName: "prowler_app_search_security_findings",
    });
    state = reduceLighthouseV2Event(state, {
      type: "tool_call.end",
      toolCallId: "tool-1",
      outcome: "success",
    });
    state = reduceLighthouseV2Event(state, {
      type: "message.delta",
      content: "Ahora voy a buscar en los criticos",
    });

    // Then
    expect(state.activityItems).toEqual([
      {
        id: "text-0",
        type: "text",
        text: "Voy a buscar los findings por severidad",
      },
      {
        id: "tool-1",
        type: "tool_call",
        name: "prowler_app_search_security_findings",
        status: "completed",
        outcome: "success",
      },
      {
        id: "text-2",
        type: "text",
        text: "Ahora voy a buscar en los criticos",
      },
    ]);
  });

  it("should mark message end as completed", () => {
    // Given
    const state = createInitialLighthouseV2StreamState("task-1");

    // When
    const next = reduceLighthouseV2Event(state, {
      type: "message.end",
      messageId: "message-1",
    });

    // Then
    expect(next.status).toBe("completed");
    expect(next.messageId).toBe("message-1");
    expect(next.activeTaskId).toBeNull();
  });

  it("should store terminal errors", () => {
    // Given
    const state = createInitialLighthouseV2StreamState("task-1");

    // When
    const next = reduceLighthouseV2Event(state, {
      type: "error",
      code: "llm_error",
      detail: "Provider failed",
    });

    // Then
    expect(next.status).toBe("error");
    expect(next.error).toEqual({
      code: "llm_error",
      detail: "Provider failed",
    });
    expect(next.activeTaskId).toBeNull();
  });

  it("should clear the task gate on disconnect so retry can recover", () => {
    // Given
    const state = createInitialLighthouseV2StreamState("task-1");

    // When
    const next = reduceLighthouseV2Event(state, { type: "disconnect" });

    // Then
    expect(next.status).toBe("disconnected");
    // activeTaskId must be cleared: leaving it set keeps canSend false and
    // makes the Retry button a no-op after a dropped SSE connection.
    expect(next.activeTaskId).toBeNull();
  });
});
