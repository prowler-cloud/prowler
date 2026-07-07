import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  createLighthouseChatStore,
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

    createSessionMock.mockResolvedValue({
      data: {
        id: "session-1",
        title: "Summarize findings",
        isArchived: false,
        insertedAt: "2026-06-24T10:00:00Z",
        updatedAt: "2026-06-24T10:00:00Z",
      },
    });
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
