import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  createLighthouseChatStore,
  selectLighthouseChatActiveSkill,
  selectLighthouseChatCanSend,
} from "@/app/(prowler)/lighthouse/_lib/chat-store";
import {
  type MockEventSource,
  stubEventSource,
} from "@/app/(prowler)/lighthouse/_lib/testing/event-source-mock";
import type {
  LighthouseV2Configuration,
  LighthouseV2Message,
  LighthouseV2SupportedModel,
  LighthouseV2SupportedProvider,
} from "@/app/(prowler)/lighthouse/_types";
import { getSkillById } from "@/lib/lighthouse/skills/registry";
import type { LighthouseContextEnvelope } from "@/types/lighthouse-context";

const {
  createSessionMock,
  getMessagesMock,
  sendMessageMock,
  updateConfigurationMock,
} = vi.hoisted(() => ({
  createSessionMock: vi.fn(),
  getMessagesMock: vi.fn(),
  sendMessageMock: vi.fn(),
  updateConfigurationMock: vi.fn(),
}));

vi.mock("@/app/(prowler)/lighthouse/_actions", () => ({
  createLighthouseV2Session: createSessionMock,
  getLighthouseV2Messages: getMessagesMock,
  sendLighthouseV2Message: sendMessageMock,
  updateLighthouseV2Configuration: updateConfigurationMock,
}));

const configurations: LighthouseV2Configuration[] = [
  {
    id: "config-openai",
    providerType: "openai",
    baseUrl: null,
    defaultModel: "gpt-5.1",
    businessContext: "Production account",
    connected: true,
    connectionLastCheckedAt: "2026-06-24T10:00:00Z",
    insertedAt: "2026-06-24T09:00:00Z",
    updatedAt: "2026-06-24T10:00:00Z",
  },
];

const modelsByProvider = {
  openai: [model("gpt-5.1")],
  bedrock: [],
  "openai-compatible": [],
};

const supportedProviders: LighthouseV2SupportedProvider[] = [
  { id: "openai", name: "OpenAI" },
  { id: "bedrock", name: "AWS Bedrock" },
  { id: "openai-compatible", name: "OpenAI Compatible" },
];

const config = { configurations, modelsByProvider, supportedProviders };

let eventSources: MockEventSource[] = [];

describe("createLighthouseChatStore", () => {
  beforeEach(() => {
    createSessionMock.mockReset();
    getMessagesMock.mockReset();
    sendMessageMock.mockReset();
    updateConfigurationMock.mockReset();
    eventSources = stubEventSource();

    createSessionMock.mockResolvedValue(sessionResult());
    getMessagesMock.mockResolvedValue({ data: [] });
    sendMessageMock.mockResolvedValue({
      data: {
        task: { id: "task-1", name: "lighthouse-run", state: "executing" },
      },
    });
    window.history.replaceState(null, "", "/");
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("resolves the connected provider's remembered model on creation", () => {
    // Given / When
    const store = makeStore();

    // Then
    expect(store.getState().selectedModelSelection).toEqual({
      providerType: "openai",
      modelId: "gpt-5.1",
    });
    expect(selectLighthouseChatCanSend(store.getState())).toBe(true);
  });

  it("creates a session and subscribes to the stream before sending (no replay buffer)", async () => {
    // Given
    const store = makeStore();

    // When
    await store.getState().submitMessage("Summarize findings");

    // Then
    expect(createSessionMock).toHaveBeenCalledWith("Summarize findings");
    expect(EventSource).toHaveBeenCalledWith(
      "/api/lighthouse/v2/sessions/session-1/event-stream",
    );
    const eventSourceOrder = vi.mocked(EventSource).mock.invocationCallOrder[0];
    const sendOrder = sendMessageMock.mock.invocationCallOrder[0];
    expect(eventSourceOrder).toBeLessThan(sendOrder);
    // The optimistic user message renders immediately and the task id is live.
    expect(store.getState().messages.at(-1)?.parts[0]?.content).toEqual({
      text: "Summarize findings",
    });
    expect(store.getState().streamState.activeTaskId).toBe("task-1");
  });

  it("captures and sends the validated context with unmodified display text", async () => {
    // Given
    const store = makeStore();
    const context = findingsContext();

    // When
    await store
      .getState()
      .submitMessage("  Summarize critical findings  ", context);

    // Then
    expect(createSessionMock).toHaveBeenCalledWith(
      "Summarize critical findings",
    );
    expect(sendMessageMock).toHaveBeenCalledWith({
      sessionId: "session-1",
      displayText: "  Summarize critical findings  ",
      context,
      provider: "openai",
      model: "gpt-5.1",
    });
    expect(store.getState().lastSubmission).toEqual({
      displayText: "  Summarize critical findings  ",
      context,
    });
  });

  it("threads a launched skill through the optimistic message and the API call", async () => {
    // Given
    const store = makeStore();
    const skill = getSkillById("triage-decision");
    if (!skill) throw new Error("Expected skill definition");

    // When
    await store.getState().submitMessage(skill.name, undefined, skill);

    // Then
    expect(sendMessageMock).toHaveBeenCalledWith(
      expect.objectContaining({
        displayText: "Triage Decision",
        skillId: "triage-decision",
      }),
    );
    expect(store.getState().messages.at(-1)?.parts[0]?.content).toMatchObject({
      text: expect.stringContaining("[PROWLER_UI_SKILL_V1]"),
      display_text: "Triage Decision",
      ui_skill: expect.objectContaining({
        skill_id: "triage-decision",
      }),
    });
    // The run is live, so the pill/progress surfaces see the active skill.
    expect(selectLighthouseChatActiveSkill(store.getState())?.id).toBe(
      "triage-decision",
    );
  });

  it("preserves an active skill stream while EventSource reconnects", async () => {
    // Given
    const store = makeStore();
    const skill = getSkillById("triage-decision");
    if (!skill) throw new Error("Expected skill definition");
    await store.getState().submitMessage(skill.name, undefined, skill);
    eventSources[0].emit("message.delta", {
      content: "Result ",
    });

    // When: the browser reports a transient failure and keeps reconnecting
    eventSources[0].fail(0 /* EventSource.CONNECTING */);
    eventSources[0].emit("message.delta", {
      content: "Checking exposure.",
    });

    // Then
    expect(store.getState().streamState).toMatchObject({
      status: "streaming",
      activeTaskId: "task-1",
      assistantText: "Result Checking exposure.",
    });
  });

  it("retries a failed skill launch with the same skill attached", async () => {
    // Given
    const store = makeStore();
    const skill = getSkillById("contextual-fix");
    if (!skill) throw new Error("Expected skill definition");
    sendMessageMock.mockResolvedValueOnce({ error: "Agent unavailable" });
    await store.getState().submitMessage(skill.name, undefined, skill);
    // The failed run is no longer active, so the skill is not "active" either.
    expect(selectLighthouseChatActiveSkill(store.getState())).toBeUndefined();

    // When
    await store.getState().retryLastMessage();

    // Then
    expect(sendMessageMock).toHaveBeenLastCalledWith(
      expect.objectContaining({ skillId: "contextual-fix" }),
    );
  });

  it("uses the model selected when submission starts", async () => {
    // Given
    const store = makeStore();
    let resolveCreate: (value: unknown) => void = () => {};
    createSessionMock.mockReturnValueOnce(
      new Promise((resolve) => {
        resolveCreate = resolve;
      }),
    );
    updateConfigurationMock.mockResolvedValue({ data: configurations[0] });
    const submitting = store.getState().submitMessage("Summarize findings");
    await vi.waitFor(() => expect(createSessionMock).toHaveBeenCalledOnce());

    // When
    await store.getState().selectModel({
      providerType: "openai",
      modelId: "gpt-5.2",
    });
    resolveCreate(sessionResult());
    await submitting;

    // Then
    expect(sendMessageMock).toHaveBeenCalledWith(
      expect.objectContaining({
        provider: "openai",
        model: "gpt-5.1",
      }),
    );
  });

  it("retries with the original context snapshot", async () => {
    // Given
    const store = makeStore();
    const context = focusedFindingsContext();
    await store.getState().submitMessage("Prioritize findings", context);
    context.items[1].label = "Mutated after send";
    eventSources[0].fail(2 /* EventSource.CLOSED */);
    sendMessageMock.mockResolvedValueOnce({
      data: {
        task: { id: "task-2", name: "lighthouse-run", state: "executing" },
      },
    });

    // When
    await store.getState().retryLastMessage();

    // Then
    expect(sendMessageMock).toHaveBeenNthCalledWith(2, {
      sessionId: "session-1",
      displayText: "Prioritize findings",
      context: focusedFindingsContext(),
      provider: "openai",
      model: "gpt-5.1",
    });
  });

  it("degrades oversized context before sending without blocking the message", async () => {
    // Given
    const store = makeStore();
    const context = oversizedFindingsContext();

    // When
    await store.getState().submitMessage("Prioritize findings", context);

    // Then
    expect(sendMessageMock).toHaveBeenCalledWith(
      expect.objectContaining({
        displayText: "Prioritize findings",
        context: {
          ...context,
          items: context.items.slice(0, 6),
        },
      }),
    );
  });

  it("does not touch the URL when syncUrlToSession is off (panel surface)", async () => {
    // Given
    const store = makeStore({ syncUrlToSession: false });
    const replaceStateSpy = vi.spyOn(window.history, "replaceState");

    // When
    await store.getState().submitMessage("Summarize findings");

    // Then
    expect(store.getState().activeSessionId).toBe("session-1");
    expect(replaceStateSpy).not.toHaveBeenCalled();
  });

  it("writes the session URL in place when syncUrlToSession is on (page surface)", async () => {
    // Given
    const store = makeStore({ syncUrlToSession: true });
    const replaceStateSpy = vi.spyOn(window.history, "replaceState");

    // When
    await store.getState().submitMessage("Summarize findings");

    // Then
    expect(replaceStateSpy).toHaveBeenCalledWith(
      null,
      "",
      "/lighthouse?session=session-1",
    );
  });

  it("reloads persisted messages and closes the stream on message.end", async () => {
    // Given
    const store = makeStore();
    await store.getState().submitMessage("Summarize findings");
    getMessagesMock.mockResolvedValue({
      data: [message("message-1", "assistant", "Persisted answer")],
    });

    // When
    eventSources[0].emit("message.end", { message_id: "message-1" });
    await vi.waitFor(() =>
      expect(getMessagesMock).toHaveBeenCalledWith("session-1"),
    );

    // Then
    await vi.waitFor(() =>
      expect(store.getState().messages[0]?.parts[0]?.content).toBe(
        "Persisted answer",
      ),
    );
    expect(eventSources[0].close).toHaveBeenCalled();
    expect(store.getState().streamState.activeTaskId).toBeNull();
  });

  it("blocks sending and refreshes messages on a 409 conflict", async () => {
    // Given
    const store = makeStore();
    sendMessageMock.mockResolvedValue({
      error: "Another run is in progress.",
      status: 409,
    });

    // When
    await store.getState().submitMessage("Summarize findings");

    // Then
    expect(store.getState().blockedByConflict).toBe(true);
    expect(store.getState().feedback).toBe("Another run is in progress.");
    expect(getMessagesMock).toHaveBeenCalledWith("session-1");
    expect(eventSources[0].close).toHaveBeenCalled();
    expect(selectLighthouseChatCanSend(store.getState())).toBe(false);
  });

  it("reconciles the optimistic message when the send fails without a conflict", async () => {
    // Given: the backend rejects the message with a plain failure
    const store = makeStore();
    sendMessageMock.mockResolvedValue({ error: "Send failed.", status: 500 });

    // When
    await store.getState().submitMessage("Summarize findings");

    // Then: feedback surfaces without blocking, and the optimistic user
    // message is reconciled against the server (it was never persisted)
    expect(store.getState().feedback).toBe("Send failed.");
    expect(store.getState().blockedByConflict).toBe(false);
    expect(getMessagesMock).toHaveBeenCalledWith("session-1");
    expect(store.getState().messages).toHaveLength(0);
  });

  it("drops a failed send once the chat points at another session", async () => {
    // Given: a send still in flight
    const store = makeStore();
    let resolveSend: (value: unknown) => void = () => {};
    sendMessageMock.mockReturnValueOnce(
      new Promise((resolve) => {
        resolveSend = resolve;
      }),
    );
    const submitting = store.getState().submitMessage("Summarize findings");
    await vi.waitFor(() => expect(sendMessageMock).toHaveBeenCalled());

    // When: the user opens another session before the send fails
    await store.getState().openSession("session-9");
    resolveSend({ error: "Send failed.", status: 500 });
    await submitting;

    // Then: the dead submission's failure never surfaces in the new session
    expect(store.getState().activeSessionId).toBe("session-9");
    expect(store.getState().feedback).toBeNull();
  });

  it("keeps a fast follow-up intact when the terminal refresh resolves late", async () => {
    // Given: a completed run whose terminal message refresh is still in flight
    const store = makeStore();
    await store.getState().submitMessage("First question");
    let resolveRefresh: (value: unknown) => void = () => {};
    getMessagesMock.mockReturnValueOnce(
      new Promise((resolve) => {
        resolveRefresh = resolve;
      }),
    );
    eventSources[0].emit("message.end", { message_id: "message-1" });
    await vi.waitFor(() =>
      expect(getMessagesMock).toHaveBeenCalledWith("session-1"),
    );

    // When: the user sends a follow-up before that refresh resolves
    sendMessageMock.mockResolvedValue({
      data: {
        task: { id: "task-2", name: "lighthouse-run", state: "executing" },
      },
    });
    await store.getState().submitMessage("Follow-up question");
    resolveRefresh({ data: [message("message-1", "assistant", "Answer")] });
    await new Promise((resolve) => setTimeout(resolve, 0));

    // Then: the stale snapshot erases neither the new optimistic message nor
    // the follow-up's task id
    expect(store.getState().streamState.activeTaskId).toBe("task-2");
    expect(store.getState().messages.at(-1)?.parts[0]?.content).toEqual({
      text: "Follow-up question",
    });
  });

  it("abandons an in-flight submit after destroy", async () => {
    // Given: destroy fires while the session create is still in flight
    const store = makeStore({ syncUrlToSession: true });
    const replaceStateSpy = vi.spyOn(window.history, "replaceState");
    let resolveCreate: (value: unknown) => void = () => {};
    createSessionMock.mockReturnValueOnce(
      new Promise((resolve) => {
        resolveCreate = resolve;
      }),
    );
    const submitting = store.getState().submitMessage("Summarize findings");
    store.getState().destroy();

    // When
    resolveCreate(sessionResult());
    await submitting;

    // Then: no URL rewrite on whatever page is now open, no orphan stream
    expect(replaceStateSpy).not.toHaveBeenCalled();
    expect(eventSources).toHaveLength(0);
  });

  it("does not replace a session opened while a new session is being created", async () => {
    // Given: creating the first session is still in flight
    const store = makeStore();
    let resolveCreate: (value: unknown) => void = () => {};
    createSessionMock.mockReturnValueOnce(
      new Promise((resolve) => {
        resolveCreate = resolve;
      }),
    );
    const submitting = store.getState().submitMessage("Summarize findings");
    await vi.waitFor(() => expect(createSessionMock).toHaveBeenCalled());

    // When: the user opens another conversation before creation resolves
    await store.getState().openSession("session-9");
    resolveCreate(sessionResult());
    await submitting;

    // Then: the stale creation cannot replace or submit into the open chat
    expect(store.getState().activeSessionId).toBe("session-9");
    expect(sendMessageMock).not.toHaveBeenCalled();
  });

  it("does not revive a session creation cancelled by a new-chat reset", async () => {
    // Given: creating the first session is still in flight
    const store = makeStore();
    let resolveCreate: (value: unknown) => void = () => {};
    createSessionMock.mockReturnValueOnce(
      new Promise((resolve) => {
        resolveCreate = resolve;
      }),
    );
    const submitting = store.getState().submitMessage("Summarize findings");
    await vi.waitFor(() => expect(createSessionMock).toHaveBeenCalled());

    // When: the user resets to a new chat before creation resolves
    store.getState().resetToNewChat();
    resolveCreate(sessionResult());
    await submitting;

    // Then
    expect(store.getState().activeSessionId).toBeNull();
    expect(sendMessageMock).not.toHaveBeenCalled();
  });

  it("keeps a replacement submission locked when an older submit settles", async () => {
    // Given: two new-chat submissions are creating sessions concurrently
    const store = makeStore();
    let resolveFirstCreate: (value: unknown) => void = () => {};
    let resolveSecondCreate: (value: unknown) => void = () => {};
    createSessionMock
      .mockReturnValueOnce(
        new Promise((resolve) => {
          resolveFirstCreate = resolve;
        }),
      )
      .mockReturnValueOnce(
        new Promise((resolve) => {
          resolveSecondCreate = resolve;
        }),
      );
    const firstSubmission = store.getState().submitMessage("First question");
    await vi.waitFor(() => expect(createSessionMock).toHaveBeenCalledOnce());
    store.getState().resetToNewChat();
    const replacementSubmission = store
      .getState()
      .submitMessage("Replacement question");
    await vi.waitFor(() => expect(createSessionMock).toHaveBeenCalledTimes(2));

    // When: the cancelled submission settles before its replacement
    resolveFirstCreate(sessionResult("session-stale", "First question"));
    await firstSubmission;

    // Then: only the replacement still owns the submission lock
    expect(store.getState().isSubmitting).toBe(true);

    resolveSecondCreate(
      sessionResult("session-current", "Replacement question"),
    );
    await replacementSubmission;
    expect(sendMessageMock).toHaveBeenCalledOnce();
    expect(sendMessageMock).toHaveBeenCalledWith(
      expect.objectContaining({
        sessionId: "session-current",
        displayText: "Replacement question",
      }),
    );
  });

  it("opens an existing session client-side without navigation", async () => {
    // Given
    const store = makeStore({ syncUrlToSession: false });
    const replaceStateSpy = vi.spyOn(window.history, "replaceState");
    getMessagesMock.mockResolvedValue({
      data: [message("message-1", "assistant", "Old answer")],
    });

    // When
    await store.getState().openSession("session-9");

    // Then
    expect(store.getState().activeSessionId).toBe("session-9");
    expect(store.getState().messages[0]?.parts[0]?.content).toBe("Old answer");
    expect(replaceStateSpy).not.toHaveBeenCalled();
  });

  it("drops a stale openSession result when the chat was reset meanwhile", async () => {
    // Given: opening a session whose message fetch is still in flight
    const store = makeStore();
    let resolveLoad: (value: unknown) => void = () => {};
    getMessagesMock.mockReturnValueOnce(
      new Promise((resolve) => {
        resolveLoad = resolve;
      }),
    );
    const opening = store.getState().openSession("session-9");

    // When: the user starts a new chat before the fetch resolves
    store.getState().resetToNewChat();
    resolveLoad({ data: [message("message-1", "assistant", "Stale answer")] });
    await opening;

    // Then: the stale messages never repopulate the reset chat
    expect(store.getState().activeSessionId).toBeNull();
    expect(store.getState().messages).toHaveLength(0);
  });

  it("resets to a new chat and closes any open stream", async () => {
    // Given
    const store = makeStore();
    await store.getState().submitMessage("Summarize findings");
    expect(store.getState().activeSessionId).toBe("session-1");

    // When
    store.getState().resetToNewChat();

    // Then
    expect(eventSources[0].close).toHaveBeenCalled();
    expect(store.getState().activeSessionId).toBeNull();
    expect(store.getState().messages).toHaveLength(0);
    expect(store.getState().streamState.activeTaskId).toBeNull();
  });

  it("resets only when the archived session is the active one", async () => {
    // Given
    const store = makeStore();
    await store.getState().submitMessage("Summarize findings");

    // When / Then: an unrelated session leaves the conversation intact
    store.getState().handleSessionArchived("session-other");
    expect(store.getState().activeSessionId).toBe("session-1");

    // When / Then: archiving the active session resets in place
    store.getState().handleSessionArchived("session-1");
    expect(store.getState().activeSessionId).toBeNull();
  });

  it("closes the stream on destroy", async () => {
    // Given
    const store = makeStore();
    await store.getState().submitMessage("Summarize findings");

    // When
    store.getState().destroy();

    // Then
    expect(eventSources[0].close).toHaveBeenCalled();
  });

  it("surfaces a connection error when the stream closes terminally", async () => {
    // Given
    const store = makeStore();
    await store.getState().submitMessage("Summarize findings");

    // When: the EventSource fails terminally (e.g. 401/404 on the SSE GET)
    eventSources[0].fail(2 /* EventSource.CLOSED */);

    // Then
    expect(store.getState().feedback).toBe(
      "Unable to connect to the response stream.",
    );
  });
});

function makeStore(
  overrides?: Partial<Parameters<typeof createLighthouseChatStore>[0]>,
) {
  return createLighthouseChatStore({
    config,
    syncUrlToSession: false,
    ...overrides,
  });
}

function sessionResult(id = "session-1", title = "Summarize findings") {
  return {
    data: {
      id,
      title,
      isArchived: false,
      insertedAt: "2026-06-24T10:00:00Z",
      updatedAt: "2026-06-24T10:00:00Z",
    },
  };
}

function model(id: string, name = id): LighthouseV2SupportedModel {
  return {
    id,
    name,
    maxInputTokens: null,
    maxOutputTokens: null,
    supportsFunctionCalling: null,
    supportsVision: null,
    supportsReasoning: null,
  };
}

function message(
  id: string,
  role: LighthouseV2Message["role"],
  content: string,
): LighthouseV2Message {
  return {
    id,
    role,
    model: null,
    tokenUsage: null,
    insertedAt: "2026-06-25T10:00:00Z",
    parts: [
      {
        id: `${id}-part`,
        type: "text",
        content,
        toolCallOutcome: null,
        insertedAt: "2026-06-25T10:00:00Z",
        updatedAt: "2026-06-25T10:00:00Z",
      },
    ],
  };
}

function findingsContext(): LighthouseContextEnvelope {
  return {
    schemaVersion: 1,
    transport: "inline",
    items: [
      {
        kind: "page",
        id: "findings",
        source: "automatic",
        scopeKey: "findings:/findings",
        label: "Findings",
        path: "/findings",
      },
    ],
  };
}

function focusedFindingsContext(): LighthouseContextEnvelope {
  const context = findingsContext();
  return {
    ...context,
    items: [
      ...context.items,
      {
        kind: "finding",
        id: "finding-1",
        source: "focused",
        scopeKey: "findings:/findings",
        label: "Focused finding",
        findingId: "finding-1",
        checkId: "aws_s3_bucket_public_access",
      },
    ],
  };
}

function oversizedFindingsContext(): LighthouseContextEnvelope {
  const context = findingsContext();
  return {
    ...context,
    items: [
      ...context.items,
      {
        kind: "finding",
        id: "finding-1",
        source: "selection",
        scopeKey: "findings:/findings",
        label: "Selected finding",
        findingId: "finding-1",
      },
      ...Array.from({ length: 6 }, (_, index) => ({
        kind: "finding" as const,
        id: `summary-${index}`,
        source: "automatic" as const,
        scopeKey: "findings:/findings",
        label: `Summary ${index} ${"x".repeat(240)}`,
        findingId: `summary-${index}`,
        checkId: `check-${index}-${"y".repeat(240)}`,
        providerUid: `provider-${index}-${"z".repeat(237)}`,
      })),
    ],
  };
}
