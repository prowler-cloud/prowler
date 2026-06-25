import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type {
  LighthouseV2Configuration,
  LighthouseV2SupportedModel,
} from "@/types/lighthouse-v2";

import { LighthouseV2ChatPage } from "./lighthouse-v2-chat-page";

const {
  cancelRunMock,
  createSessionMock,
  getMessagesMock,
  pushMock,
  sendMessageMock,
} = vi.hoisted(() => ({
  cancelRunMock: vi.fn(),
  createSessionMock: vi.fn(),
  getMessagesMock: vi.fn(),
  pushMock: vi.fn(),
  sendMessageMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({
    push: pushMock,
  }),
}));

vi.mock("@/actions/lighthouse-v2/lighthouse-v2", () => ({
  cancelLighthouseV2Run: cancelRunMock,
  createLighthouseV2Session: createSessionMock,
  getLighthouseV2Messages: getMessagesMock,
  sendLighthouseV2Message: sendMessageMock,
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
    pushMock.mockReset();
    sendMessageMock.mockReset();

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

  it("uses the neutral page background instead of the global app background token", () => {
    // Given / When
    const { container } = renderPage();

    // Then
    expect(container.firstElementChild).toHaveClass("bg-bg-neutral-primary");
    expect(container.firstElementChild).not.toHaveClass("bg-background");
  });

  it("does not render provider or model selectors in the chat composer", () => {
    // Given / When
    renderPage();

    // Then
    expect(screen.queryByRole("combobox")).not.toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Lighthouse settings" }),
    ).toHaveAttribute("href", "/lighthouse/config");
  });

  it("sends messages with the connected default provider and model from configuration", async () => {
    // Given
    const user = userEvent.setup();
    renderPage();

    // When
    await user.type(
      screen.getByRole("textbox", { name: "Message" }),
      ["Summarize findings", "{Enter}"].join(""),
    );

    // Then
    await waitFor(() =>
      expect(sendMessageMock).toHaveBeenCalledWith({
        sessionId: "session-1",
        text: "Summarize findings",
        provider: "openai",
        model: "gpt-5.1",
      }),
    );
    expect(createSessionMock).toHaveBeenCalledWith("Summarize findings");
    expect(pushMock).toHaveBeenCalledWith("/lighthouse?session=session-1");
  });

  it("closes an active stream when the chat unmounts", async () => {
    // Given
    const user = userEvent.setup();
    const closeMock = vi.fn();
    const eventSourceMock = vi.fn(function MockEventSource(
      this: Record<string, unknown>,
    ) {
      this.addEventListener = vi.fn();
      this.close = closeMock;
    });
    vi.stubGlobal("EventSource", eventSourceMock);
    sendMessageMock.mockResolvedValue({
      data: {
        task: {
          id: "task-1",
          name: "lighthouse-run",
          state: "executing",
        },
        streamUrl: "/api/stream",
      },
    });
    const { unmount } = renderPage({ initialSessionId: "session-1" });

    // When
    await user.type(
      screen.getByRole("textbox", { name: "Message" }),
      ["Summarize findings", "{Enter}"].join(""),
    );
    await waitFor(() =>
      expect(eventSourceMock).toHaveBeenCalledWith("/api/stream"),
    );
    unmount();

    // Then
    expect(closeMock).toHaveBeenCalledTimes(1);
  });
});

function renderPage(
  props?: Partial<Parameters<typeof LighthouseV2ChatPage>[0]>,
) {
  return render(
    <LighthouseV2ChatPage
      configurations={props?.configurations ?? configurations}
      modelsByProvider={props?.modelsByProvider ?? modelsByProvider}
      initialSessionId={props?.initialSessionId}
      initialMessages={props?.initialMessages ?? []}
      initialPrompt={props?.initialPrompt}
    />,
  );
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
