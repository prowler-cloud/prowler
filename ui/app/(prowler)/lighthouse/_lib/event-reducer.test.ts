import { describe, expect, it } from "vitest";

import {
  createInitialLighthouseV2StreamState,
  reduceLighthouseV2Event,
} from "./event-reducer";

describe("event-reducer skill steps", () => {
  it("should strip step markers from the text and track the current step", () => {
    // Given
    const state = createInitialLighthouseV2StreamState("task-1", true);

    // When
    const next = reduceLighthouseV2Event(state, {
      type: "message.delta",
      content: "[[step:1]]Gathering context.",
    });

    // Then
    expect(next.currentStep).toBe(1);
    expect(next.assistantText).toBe("Gathering context.");
    expect(next.activityItems).toEqual([
      { id: "text-0", type: "text", text: "Gathering context." },
    ]);
  });

  it("should assemble a marker split across two deltas without leaking it", () => {
    // Given
    let state = createInitialLighthouseV2StreamState("task-1", true);
    state = reduceLighthouseV2Event(state, {
      type: "message.delta",
      content: "Done.\n[[ste",
    });
    expect(state.assistantText).toBe("Done.\n");
    expect(state.currentStep).toBeNull();

    // When
    state = reduceLighthouseV2Event(state, {
      type: "message.delta",
      content: "p:3]]Checking exposure.",
    });

    // Then
    expect(state.currentStep).toBe(3);
    expect(state.assistantText).toBe("Done.\nChecking exposure.");
  });

  it("should tag tool calls with the step active when they start", () => {
    // Given
    let state = createInitialLighthouseV2StreamState("task-1", true);
    state = reduceLighthouseV2Event(state, {
      type: "message.delta",
      content: "[[step:2]]Enumerating identities.",
    });

    // When
    state = reduceLighthouseV2Event(state, {
      type: "tool_call.start",
      toolCallId: "tool-1",
      toolName: "list_role_attachments",
    });

    // Then
    const toolItem = state.activityItems.at(-1);
    expect(toolItem).toMatchObject({ id: "tool-1", step: 2 });
  });

  it("should flush a never-completed partial marker as text when the message ends", () => {
    // Given
    let state = createInitialLighthouseV2StreamState("task-1", true);
    state = reduceLighthouseV2Event(state, {
      type: "message.delta",
      content: "See the array[",
    });
    expect(state.assistantText).toBe("See the array");

    // When
    state = reduceLighthouseV2Event(state, {
      type: "message.end",
      messageId: "message-1",
    });

    // Then
    expect(state.assistantText).toBe("See the array[");
    expect(state.activityItems.at(-1)).toMatchObject({
      type: "text",
      text: "See the array[",
    });
  });

  it("should flush a held partial marker as text on a terminal error", () => {
    // Given
    let state = createInitialLighthouseV2StreamState("task-1", true);
    state = reduceLighthouseV2Event(state, {
      type: "message.delta",
      content: "Result[",
    });
    expect(state.assistantText).toBe("Result");

    // When
    state = reduceLighthouseV2Event(state, {
      type: "error",
      code: "llm_error",
      detail: "Provider failed",
    });

    // Then: the "[" is not silently dropped
    expect(state.assistantText).toBe("Result[");
    expect(state.markerCarry).toBe("");
    expect(state.activityItems.at(-1)).toMatchObject({
      type: "text",
      text: "Result[",
    });
  });

  it("should flush a held partial marker as text on disconnect", () => {
    // Given: disconnected streams never replay, so the carry cannot complete
    let state = createInitialLighthouseV2StreamState("task-1", true);
    state = reduceLighthouseV2Event(state, {
      type: "message.delta",
      content: "Result[",
    });

    // When
    state = reduceLighthouseV2Event(state, { type: "disconnect" });

    // Then
    expect(state.assistantText).toBe("Result[");
    expect(state.markerCarry).toBe("");
  });
});

describe("event-reducer", () => {
  it("should preserve step-like text in a regular chat response", () => {
    // Given
    const state = createInitialLighthouseV2StreamState("task-1");

    // When
    const next = reduceLighthouseV2Event(state, {
      type: "message.delta",
      content: "Use [[step:1]] as a literal example.",
    });

    // Then
    expect(next.assistantText).toBe("Use [[step:1]] as a literal example.");
    expect(next.currentStep).toBeNull();
  });

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
      toolName: "prowler_search_security_findings",
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
        name: "prowler_search_security_findings",
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
