import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { type ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  LIGHTHOUSE_V2_SESSIONS_CHANGED_EVENT,
  notifyLighthouseV2SessionArchived,
} from "@/app/(prowler)/lighthouse/_lib/session-events";
import type {
  LighthouseV2Configuration,
  LighthouseV2Message,
  LighthouseV2SupportedModel,
  LighthouseV2SupportedProvider,
} from "@/app/(prowler)/lighthouse/_types";

import { LighthouseV2ChatPage } from "./lighthouse-v2-chat-page";

// Controllable EventSource mock: records each instance so tests can drive
// named SSE events and connection failures, while still being a vi.fn so
// `expect(EventSource).toHaveBeenCalledWith(...)` keeps working.
interface MockEventSource {
  url: string;
  readyState: number;
  onerror: ((event: Event) => void) | null;
  listeners: Map<string, Set<EventListener>>;
  addEventListener: (type: string, cb: EventListener) => void;
  close: ReturnType<typeof vi.fn>;
  emit: (type: string, data: unknown) => void;
  fail: (readyState: number) => void;
}

let eventSources: MockEventSource[] = [];

function stubEventSource() {
  eventSources = [];
  const EventSourceMock = vi.fn(function (this: MockEventSource, url: string) {
    this.url = url;
    this.readyState = 0;
    this.onerror = null;
    this.listeners = new Map();
    this.addEventListener = (type: string, cb: EventListener) => {
      const set = this.listeners.get(type) ?? new Set<EventListener>();
      set.add(cb);
      this.listeners.set(type, set);
    };
    this.close = vi.fn(() => {
      this.readyState = 2;
    });
    this.emit = (type: string, data: unknown) => {
      const event = new MessageEvent(type, { data: JSON.stringify(data) });
      this.listeners.get(type)?.forEach((cb) => cb(event));
    };
    this.fail = (readyState: number) => {
      this.readyState = readyState;
      this.onerror?.(new Event("error"));
    };
    eventSources.push(this);
  });
  Object.assign(EventSourceMock, { CONNECTING: 0, OPEN: 1, CLOSED: 2 });
  vi.stubGlobal("EventSource", EventSourceMock);
}

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

// Streamdown pulls in shiki/wasm syntax highlighting that doesn't run under
// jsdom; render its text passthrough so message bodies are still assertable.
vi.mock("streamdown", () => ({
  Streamdown: ({ children }: { children: ReactNode }) => <>{children}</>,
  defaultRehypePlugins: { katex: undefined, harden: undefined },
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
  {
    id: "config-bedrock",
    providerType: "bedrock",
    baseUrl: null,
    defaultModel: "anthropic.claude-4",
    businessContext: "Production account",
    connected: true,
    connectionLastCheckedAt: "2026-06-23T10:00:00Z",
    insertedAt: "2026-06-23T09:00:00Z",
    updatedAt: "2026-06-23T10:00:00Z",
  },
];

const modelsByProvider = {
  openai: [model("gpt-5.1"), model("gpt-4.1")],
  bedrock: [model("anthropic.claude-4")],
  "openai-compatible": [model("llama-3.3")],
};

const supportedProviders: LighthouseV2SupportedProvider[] = [
  { id: "openai", name: "OpenAI" },
  { id: "bedrock", name: "AWS Bedrock" },
  { id: "openai-compatible", name: "OpenAI Compatible" },
];

describe("LighthouseV2ChatPage", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "ResizeObserver",
      class ResizeObserver {
        observe = vi.fn();
        unobserve = vi.fn();
        disconnect = vi.fn();
      },
    );
    Object.defineProperty(Element.prototype, "scrollIntoView", {
      configurable: true,
      value: vi.fn(),
    });
    createSessionMock.mockReset();
    getMessagesMock.mockReset();
    sendMessageMock.mockReset();
    updateConfigurationMock.mockReset();
    // The mock never fires "open": the client must POST the message without
    // waiting for it (the backend sends no bytes until the worker emits, which
    // only happens after the POST). This is the regression guard for the
    // open-gate deadlock.
    stubEventSource();

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
        task: {
          id: "task-1",
          name: "lighthouse-run",
          state: "executing",
        },
      },
    });
    updateConfigurationMock.mockResolvedValue({ data: configurations[1] });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("renders the searchable model selector and settings shortcut", () => {
    // Given / When
    renderPage();

    // Then
    expect(screen.getByRole("combobox", { name: "Model" })).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Lighthouse AI settings" }),
    ).toHaveAttribute("href", "/lighthouse/settings");
  });

  it("shows the current OpenAI model without a selector when OpenAI is the only connected provider", () => {
    // Given / When
    renderPage({
      configurations: [
        { ...configurations[0], defaultModel: "gpt-5.1", connected: true },
        { ...configurations[1], connected: false },
      ],
      modelsByProvider: {
        openai: [model("gpt-5.1", "GPT-5.1")],
        bedrock: [model("anthropic.claude-4")],
        "openai-compatible": [model("llama-3.3")],
      },
    });

    // Then
    expect(
      screen.queryByRole("combobox", { name: "Model" }),
    ).not.toBeInTheDocument();
    const currentModel = screen.getByLabelText("Current model: OpenAI GPT-5.1");
    expect(within(currentModel).getByText("OpenAI")).toBeInTheDocument();
    expect(within(currentModel).getByText("GPT-5.1")).toBeInTheDocument();
  });

  it("defaults to gpt-5.5 when OpenAI has no remembered model", () => {
    // Given / When
    renderPage({
      configurations: [
        { ...configurations[0], defaultModel: null, connected: true },
        { ...configurations[1], connected: false },
      ],
      modelsByProvider: {
        openai: [model("gpt-4.1", "GPT-4.1"), model("gpt-5.5", "GPT-5.5")],
        bedrock: [model("anthropic.claude-4")],
        "openai-compatible": [model("llama-3.3")],
      },
    });

    // Then
    const currentModel = screen.getByLabelText("Current model: OpenAI GPT-5.5");
    expect(within(currentModel).getByText("GPT-5.5")).toBeInTheDocument();
  });

  it("uses the AWS onboarding quick prompt instead of the docs prompt", async () => {
    // Given
    const user = userEvent.setup();
    renderPage();

    // When
    await user.click(
      screen.getByRole("button", {
        name: "How can I onboard to my AWS account?",
      }),
    );

    // Then
    expect(
      screen.queryByRole("button", { name: "Docs" }),
    ).not.toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: "Message" })).toHaveValue(
      "How can I onboard to my AWS account?",
    );
  });

  it("shows model names in the selector while keeping model ids for persistence", async () => {
    // Given
    const user = userEvent.setup();
    renderPage({
      configurations: [
        { ...configurations[0], defaultModel: "gpt-5.1" },
        {
          ...configurations[1],
          defaultModel: "us.anthropic.claude-sonnet-4-20250514-v1:0",
        },
      ],
      modelsByProvider: {
        openai: [model("gpt-5.1", "GPT-5.1")],
        bedrock: [
          model(
            "us.anthropic.claude-sonnet-4-20250514-v1:0",
            "Claude Sonnet 4",
          ),
        ],
        "openai-compatible": [],
      },
    });

    // When
    const modelSelector = screen.getByRole("combobox", { name: "Model" });
    await user.click(modelSelector);

    // Then
    expect(modelSelector).toHaveTextContent("GPT-5.1");
    expect(
      await screen.findByRole("option", { name: "Claude Sonnet 4" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByText("us.anthropic.claude-sonnet-4-20250514-v1:0"),
    ).not.toBeInTheDocument();

    // When
    await user.click(screen.getByRole("option", { name: "Claude Sonnet 4" }));

    // Then
    await waitFor(() =>
      expect(updateConfigurationMock).toHaveBeenCalledWith("config-bedrock", {
        defaultModel: "us.anthropic.claude-sonnet-4-20250514-v1:0",
      }),
    );
    expect(modelSelector).toHaveTextContent("Claude Sonnet 4");
  });

  it("uses supported provider names as model selector section headings", async () => {
    // Given
    const user = userEvent.setup();
    renderPage({
      configurations: [
        ...configurations,
        {
          id: "config-openai-compatible",
          providerType: "openai-compatible",
          baseUrl: "https://example.com/v1",
          defaultModel: "llama-3.3",
          businessContext: "Production account",
          connected: true,
          connectionLastCheckedAt: "2026-06-22T10:00:00Z",
          insertedAt: "2026-06-22T09:00:00Z",
          updatedAt: "2026-06-22T10:00:00Z",
        },
      ],
      supportedProviders,
    });

    // When
    await user.click(screen.getByRole("combobox", { name: "Model" }));

    // Then
    expect(await screen.findByText("AWS Bedrock")).toBeInTheDocument();
    expect(screen.getByText("OpenAI Compatible")).toBeInTheDocument();
    expect(screen.queryByText("Amazon Bedrock")).not.toBeInTheDocument();
  });

  it("uses the tuned scrollbar and bottom fade without a composer separator", () => {
    // Given / When
    const { container } = renderPage({
      initialMessages: [message("message-1", "assistant", "Existing answer")],
    });

    // Then
    const conversation = screen.getByRole("log");
    const scrollViewport = conversation.firstElementChild as HTMLElement;
    const content = scrollViewport.firstElementChild as HTMLElement;
    const scrollFade = container.querySelector(
      '[data-slot="lighthouse-v2-chat-scroll-fade"]',
    );

    expect(conversation).toHaveClass("h-full", "min-h-0");
    expect(conversation.parentElement).toHaveClass("flex", "overflow-hidden");
    expect(scrollViewport).toHaveClass(
      "minimal-scrollbar",
      "overflow-x-hidden",
      "overflow-y-auto",
    );
    expect(content).toHaveClass("pb-20");
    expect(scrollFade).toHaveClass(
      "pointer-events-none",
      "absolute",
      "bottom-0",
      "right-2",
      "h-16",
      "bg-gradient-to-t",
      "from-bg-neutral-secondary",
      "to-transparent",
    );
    expect(
      container.querySelector(
        '[data-slot="lighthouse-v2-chat-composer-panel"]',
      ),
    ).not.toHaveClass("border-t");
  });

  it("opens the highest-priority connected provider with its remembered model", async () => {
    // Given: both OpenAI and Bedrock are connected; OpenAI outranks Bedrock
    const user = userEvent.setup();
    const replaceStateSpy = vi.spyOn(window.history, "replaceState");
    renderPage();

    // When
    await user.type(
      screen.getByRole("textbox", { name: "Message" }),
      ["Summarize findings", "{Enter}"].join(""),
    );

    // Then: the message is sent with OpenAI and its remembered defaultModel,
    // even though EventSource never fires "open"
    await waitFor(() =>
      expect(sendMessageMock).toHaveBeenCalledWith({
        sessionId: "session-1",
        text: "Summarize findings",
        provider: "openai",
        model: "gpt-5.1",
      }),
    );
    expect(createSessionMock).toHaveBeenCalledWith("Summarize findings");
    // The session URL is set in place (no router navigation / remount)
    expect(replaceStateSpy).toHaveBeenCalledWith(
      null,
      "",
      "/lighthouse?session=session-1",
    );
    // The stream is opened against our same-origin SSE proxy (not the
    // cross-origin API host), so the browser EventSource can actually connect.
    expect(EventSource).toHaveBeenCalledWith(
      "/api/lighthouse/v2/sessions/session-1/event-stream",
    );
    replaceStateSpy.mockRestore();
  });

  it("opens a lower-priority provider when the higher-priority one is disconnected", async () => {
    // Given: only Bedrock is connected
    const user = userEvent.setup();
    renderPage({
      configurations: [
        { ...configurations[0], connected: false },
        configurations[1],
      ],
    });

    // When
    await user.type(
      screen.getByRole("textbox", { name: "Message" }),
      ["Summarize findings", "{Enter}"].join(""),
    );

    // Then
    await waitFor(() =>
      expect(sendMessageMock).toHaveBeenCalledWith(
        expect.objectContaining({
          provider: "bedrock",
          model: "anthropic.claude-4",
        }),
      ),
    );
  });

  it("falls back to the first supported model when the remembered model is unsupported", async () => {
    // Given: OpenAI's remembered default model is no longer offered
    const user = userEvent.setup();
    renderPage({
      configurations: [
        { ...configurations[0], defaultModel: "missing-model" },
        configurations[1],
      ],
    });

    // When
    await user.type(
      screen.getByRole("textbox", { name: "Message" }),
      ["Summarize findings", "{Enter}"].join(""),
    );

    // Then: OpenAI stays selected (highest priority) but on its first model
    await waitFor(() =>
      expect(sendMessageMock).toHaveBeenCalledWith(
        expect.objectContaining({
          provider: "openai",
          model: "gpt-5.1",
        }),
      ),
    );
  });

  it("persists the selected chat model as that provider's default", async () => {
    // Given
    const user = userEvent.setup();
    renderPage();

    // When
    await user.click(screen.getByRole("combobox", { name: "Model" }));
    await user.click(
      await screen.findByRole("option", { name: "anthropic.claude-4" }),
    );

    // Then: only the chosen provider's config is updated, by id
    await waitFor(() =>
      expect(updateConfigurationMock).toHaveBeenCalledWith("config-bedrock", {
        defaultModel: "anthropic.claude-4",
      }),
    );
  });

  it("keeps the chosen model applied and surfaces the backend reason when saving the default fails", async () => {
    // Given
    const user = userEvent.setup();
    updateConfigurationMock.mockResolvedValue({
      error: "Invalid model 'anthropic.claude-4' for provider 'bedrock'.",
      status: 400,
    });
    renderPage();

    // When
    await user.click(screen.getByRole("combobox", { name: "Model" }));
    await user.click(
      await screen.findByRole("option", { name: "anthropic.claude-4" }),
    );

    // Then: the failed save shows the real backend message as an error alert,
    // and the selection stays applied so the connected provider remains usable.
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Invalid model 'anthropic.claude-4' for provider 'bedrock'.",
    );
    expect(screen.getByRole("combobox", { name: "Model" })).toHaveTextContent(
      "anthropic.claude-4",
    );
  });

  it("updates the URL before notifying session history listeners", async () => {
    // Given
    const user = userEvent.setup();
    const notifiedUrls: string[] = [];
    const recordCurrentUrl = () => {
      notifiedUrls.push(`${window.location.pathname}${window.location.search}`);
    };

    try {
      // Register inside the try so a throw in renderPage() can't leak the
      // listener into later tests (the finally only runs if we entered the try).
      window.addEventListener(
        LIGHTHOUSE_V2_SESSIONS_CHANGED_EVENT,
        recordCurrentUrl,
      );
      renderPage();

      // When
      await user.type(
        screen.getByRole("textbox", { name: "Message" }),
        ["Summarize findings", "{Enter}"].join(""),
      );

      // Then
      await waitFor(() => expect(notifiedUrls.length).toBeGreaterThan(0));
      expect(notifiedUrls[0]).toBe("/lighthouse?session=session-1");
    } finally {
      window.removeEventListener(
        LIGHTHOUSE_V2_SESSIONS_CHANGED_EVENT,
        recordCurrentUrl,
      );
    }
  });

  it("subscribes to the stream before sending the message (no replay buffer)", async () => {
    // Given
    const user = userEvent.setup();
    renderPage();

    // When
    await user.type(
      screen.getByRole("textbox", { name: "Message" }),
      ["Summarize findings", "{Enter}"].join(""),
    );

    // Then: the EventSource must be constructed before the POST, otherwise
    // early tokens emitted by the worker would be lost (backend has no replay).
    await waitFor(() => expect(sendMessageMock).toHaveBeenCalled());
    const eventSourceOrder = vi.mocked(EventSource).mock.invocationCallOrder[0];
    const sendOrder = sendMessageMock.mock.invocationCallOrder[0];
    expect(eventSourceOrder).toBeLessThan(sendOrder);
  });

  it("renders a copy button (copies text) and an ISO timestamp under each message", async () => {
    // Given
    const user = userEvent.setup();
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText },
      configurable: true,
    });
    const { container } = renderPage({
      initialMessages: [message("message-1", "assistant", "Existing answer")],
    });

    // When
    await user.click(screen.getByRole("button", { name: "Copy message" }));

    // Then: copies the message text, and the timestamp carries the raw ISO
    expect(writeText).toHaveBeenCalledWith("Existing answer");
    expect(container.querySelector("time")).toHaveAttribute(
      "datetime",
      "2026-06-25T10:00:00Z",
    );
  });

  it("renders streamed deltas and reloads persisted messages on message.end", async () => {
    // Given
    const user = userEvent.setup();
    renderPage();
    await user.type(
      screen.getByRole("textbox", { name: "Message" }),
      ["Summarize findings", "{Enter}"].join(""),
    );
    await waitFor(() => expect(eventSources).toHaveLength(1));
    const source = eventSources[0];

    // When a delta arrives, it renders live
    act(() => source.emit("message.delta", { content: "Hello there" }));
    expect(await screen.findByText("Hello there")).toBeInTheDocument();

    // When the run ends, the full persisted message is reloaded from the DB
    act(() => source.emit("message.end", { message_id: "message-1" }));
    await waitFor(() =>
      expect(getMessagesMock).toHaveBeenCalledWith("session-1"),
    );
    expect(source.close).toHaveBeenCalled();
  });

  it("resets to a new chat when the live-created session is archived from the sidebar", async () => {
    // Given: a session created in this chat (its URL was set via replaceState,
    // so the sidebar cannot see it in Next's search params)
    const user = userEvent.setup();
    const replaceStateSpy = vi.spyOn(window.history, "replaceState");
    renderPage();
    await user.type(
      screen.getByRole("textbox", { name: "Message" }),
      ["Summarize findings", "{Enter}"].join(""),
    );
    await waitFor(() => expect(sendMessageMock).toHaveBeenCalled());

    // When: the sidebar archives that same session
    act(() => notifyLighthouseV2SessionArchived("session-1"));

    // Then: the chat resets in place and the URL leaves the dead session
    await waitFor(() =>
      expect(replaceStateSpy).toHaveBeenCalledWith(null, "", "/lighthouse"),
    );
    expect(screen.queryByText("Summarize findings")).not.toBeInTheDocument();
    expect(eventSources[0].close).toHaveBeenCalled();
    replaceStateSpy.mockRestore();
  });

  it("drops a stale message reload that resolves after the session is archived", async () => {
    // Given: a live session whose message.end reload is still in flight
    const user = userEvent.setup();
    let resolveReload: (value: unknown) => void = () => {};
    getMessagesMock.mockReturnValueOnce(
      new Promise((resolve) => {
        resolveReload = resolve;
      }),
    );
    renderPage();
    await user.type(
      screen.getByRole("textbox", { name: "Message" }),
      ["Summarize findings", "{Enter}"].join(""),
    );
    await waitFor(() => expect(eventSources).toHaveLength(1));

    // When: the run ends (starting the async reload) and, before it resolves,
    // the open session is archived and the chat resets
    act(() => eventSources[0].emit("message.end", { message_id: "message-1" }));
    await waitFor(() =>
      expect(getMessagesMock).toHaveBeenCalledWith("session-1"),
    );
    act(() => notifyLighthouseV2SessionArchived("session-1"));

    // The reload finally resolves with the (now archived) session's messages
    await act(async () => {
      resolveReload({
        data: [message("message-1", "assistant", "Archived answer")],
      });
    });

    // Then: the stale reload is ignored so the reset chat is not repopulated
    expect(screen.queryByText("Archived answer")).not.toBeInTheDocument();
  });

  it("keeps the conversation when a different session is archived", async () => {
    // Given
    renderPage({
      initialSessionId: "session-2",
      initialMessages: [message("message-1", "assistant", "Existing answer")],
    });

    // When
    act(() => notifyLighthouseV2SessionArchived("session-other"));

    // Then
    expect(screen.getByText("Existing answer")).toBeInTheDocument();
  });

  it("surfaces a connection error when the stream closes without retrying", async () => {
    // Given
    const user = userEvent.setup();
    renderPage();
    await user.type(
      screen.getByRole("textbox", { name: "Message" }),
      ["Summarize findings", "{Enter}"].join(""),
    );
    await waitFor(() => expect(eventSources).toHaveLength(1));

    // When the EventSource fails terminally (e.g. 401/404 on the SSE GET)
    act(() => eventSources[0].fail(2 /* EventSource.CLOSED */));

    // Then a clear error is shown instead of an endless "Reconnecting" spinner
    expect(
      await screen.findByText("Unable to connect to the response stream."),
    ).toBeInTheDocument();
  });
});

type RenderPageProps = Partial<Parameters<typeof LighthouseV2ChatPage>[0]>;

function renderPage(props?: RenderPageProps) {
  const componentProps = {
    configurations: props?.configurations ?? configurations,
    modelsByProvider: props?.modelsByProvider ?? modelsByProvider,
    supportedProviders: props?.supportedProviders ?? supportedProviders,
    initialSessionId: props?.initialSessionId,
    initialMessages: props?.initialMessages ?? [],
    initialPrompt: props?.initialPrompt,
  } satisfies Parameters<typeof LighthouseV2ChatPage>[0];

  return render(<LighthouseV2ChatPage {...componentProps} />);
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
