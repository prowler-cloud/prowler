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

  it("should mark run cancellation as terminal without error", () => {
    // Given
    const state = createInitialLighthouseV2StreamState("task-1");

    // When
    const next = reduceLighthouseV2Event(state, {
      type: "run.cancelled",
      taskId: "task-1",
    });

    // Then
    expect(next.status).toBe("cancelled");
    expect(next.error).toBeUndefined();
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

  it("should mark disconnect as recoverable", () => {
    // Given
    const state = createInitialLighthouseV2StreamState("task-1");

    // When
    const next = reduceLighthouseV2Event(state, { type: "disconnect" });

    // Then
    expect(next.status).toBe("disconnected");
    expect(next.activeTaskId).toBe("task-1");
  });
});
