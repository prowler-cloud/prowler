import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { type ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type {
  LighthouseV2Configuration,
  LighthouseV2Message,
  LighthouseV2SupportedModel,
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

const { cancelRunMock, createSessionMock, getMessagesMock, sendMessageMock } =
  vi.hoisted(() => ({
    cancelRunMock: vi.fn(),
    createSessionMock: vi.fn(),
    getMessagesMock: vi.fn(),
    sendMessageMock: vi.fn(),
  }));

vi.mock("@/app/(prowler)/lighthouse/_actions", () => ({
  cancelLighthouseV2Run: cancelRunMock,
  createLighthouseV2Session: createSessionMock,
  getLighthouseV2Messages: getMessagesMock,
  sendLighthouseV2Message: sendMessageMock,
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
    businessContext: "AWS landing zone",
    connected: true,
    connectionLastCheckedAt: "2026-06-23T10:00:00Z",
    insertedAt: "2026-06-23T09:00:00Z",
    updatedAt: "2026-06-23T10:00:00Z",
  },
];

const modelsByProvider = {
  openai: [model("gpt-5.1")],
  bedrock: [model("anthropic.claude-4")],
  "openai-compatible": [model("llama-3.3")],
};

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
    cancelRunMock.mockReset();
    createSessionMock.mockReset();
    getMessagesMock.mockReset();
    sendMessageMock.mockReset();
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
        activeTaskId: null,
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
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("does not render provider or model selectors in the chat composer", () => {
    // Given / When
    renderPage();

    // Then
    expect(screen.queryByRole("combobox")).not.toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Lighthouse AI settings" }),
    ).toHaveAttribute("href", "/lighthouse/settings");
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

  it("sends messages with the connected default provider and model from configuration", async () => {
    // Given
    const user = userEvent.setup();
    const replaceStateSpy = vi.spyOn(window.history, "replaceState");
    renderPage();

    // When
    await user.type(
      screen.getByRole("textbox", { name: "Message" }),
      ["Summarize findings", "{Enter}"].join(""),
    );

    // Then: the message is sent even though EventSource never fires "open"
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
    initialSessionId: props?.initialSessionId,
    initialMessages: props?.initialMessages ?? [],
    initialPrompt: props?.initialPrompt,
    initialActiveTaskId: props?.initialActiveTaskId,
    initialStreamUrl: props?.initialStreamUrl,
  } satisfies Parameters<typeof LighthouseV2ChatPage>[0];

  return render(<LighthouseV2ChatPage {...componentProps} />);
}

function model(id: string): LighthouseV2SupportedModel {
  return {
    id,
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
