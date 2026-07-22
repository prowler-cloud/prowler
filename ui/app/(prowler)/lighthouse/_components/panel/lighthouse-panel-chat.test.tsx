import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { type ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { resetPanelChatStoreForTests } from "@/app/(prowler)/lighthouse/_lib/panel-chat-store";
import { notifyLighthouseV2ConfigurationsChanged } from "@/app/(prowler)/lighthouse/_lib/session-events";
import { stubEventSource } from "@/app/(prowler)/lighthouse/_lib/testing/event-source-mock";
import type {
  LighthouseV2Configuration,
  LighthouseV2Session,
  LighthouseV2SupportedModel,
} from "@/app/(prowler)/lighthouse/_types";

import {
  LighthousePanelChat,
  resetPanelChatConfigCacheForTests,
} from "./lighthouse-panel-chat";
import { LighthousePanelHeaderActions } from "./lighthouse-panel-header-actions";

const {
  getConfigurationsMock,
  getSupportedProvidersMock,
  getSupportedModelsMock,
  getSessionsMock,
  archiveSessionMock,
  createSessionMock,
  getMessagesMock,
  sendMessageMock,
  updateConfigurationMock,
} = vi.hoisted(() => ({
  getConfigurationsMock: vi.fn(),
  getSupportedProvidersMock: vi.fn(),
  getSupportedModelsMock: vi.fn(),
  getSessionsMock: vi.fn(),
  archiveSessionMock: vi.fn(),
  createSessionMock: vi.fn(),
  getMessagesMock: vi.fn(),
  sendMessageMock: vi.fn(),
  updateConfigurationMock: vi.fn(),
}));

vi.mock("@/app/(prowler)/lighthouse/_actions", () => ({
  getLighthouseV2Configurations: getConfigurationsMock,
  getLighthouseV2SupportedProviders: getSupportedProvidersMock,
  getLighthouseV2SupportedModels: getSupportedModelsMock,
  getLighthouseV2Sessions: getSessionsMock,
  archiveLighthouseV2Session: archiveSessionMock,
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
];

describe("LighthousePanelChat", () => {
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
    getConfigurationsMock.mockReset();
    getSupportedProvidersMock.mockReset();
    getSupportedModelsMock.mockReset();
    getSessionsMock.mockReset();
    archiveSessionMock.mockReset();
    getMessagesMock.mockReset();
    stubEventSource();
    resetPanelChatStoreForTests();
    resetPanelChatConfigCacheForTests();

    getConfigurationsMock.mockResolvedValue({ data: configurations });
    getSupportedProvidersMock.mockResolvedValue({
      data: [
        { id: "openai", name: "OpenAI" },
        { id: "bedrock", name: "AWS Bedrock" },
        { id: "openai-compatible", name: "OpenAI Compatible" },
      ],
    });
    getSupportedModelsMock.mockResolvedValue({ data: [model("gpt-5.1")] });
    getSessionsMock.mockResolvedValue({ data: [] });
    getMessagesMock.mockResolvedValue({ data: [] });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("shows a loading skeleton while the config loads", () => {
    // Given: a config fetch that never resolves within the assertion window
    getConfigurationsMock.mockReturnValue(new Promise(() => {}));

    // When
    render(<LighthousePanelChat />);

    // Then
    expect(screen.getByLabelText("Loading Lighthouse AI")).toBeInTheDocument();
  });

  it("shows the error state with a Retry that reloads the config", async () => {
    // Given
    getConfigurationsMock.mockResolvedValueOnce({
      error: "Something went wrong.",
      status: 500,
    });
    const user = userEvent.setup();
    render(<LighthousePanelChat />);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Something went wrong.",
    );

    // When: retrying after the backend recovers
    await user.click(screen.getByRole("button", { name: "Retry" }));

    // Then
    expect(
      await screen.findByRole("textbox", { name: "Message" }),
    ).toBeInTheDocument();
  });

  it("shows an in-panel connect CTA instead of redirecting when no LLM is connected", async () => {
    // Given
    getConfigurationsMock.mockResolvedValue({
      data: [{ ...configurations[0], connected: false }],
    });

    // When
    render(<LighthousePanelChat />);

    // Then
    expect(
      await screen.findByRole("link", { name: "Connect an LLM provider" }),
    ).toHaveAttribute("href", "/lighthouse/settings");
  });

  it("renders the chat composer and recent chats once ready", async () => {
    // Given
    getSessionsMock.mockResolvedValue({
      data: [session("session-1", "Counting critical findings")],
    });

    // When
    render(<LighthousePanelChat />);

    // Then: composer is live and the empty state lists recent chats
    expect(
      await screen.findByRole("textbox", { name: "Message" }),
    ).toBeInTheDocument();
    expect(await screen.findByText("Recent chats")).toBeInTheDocument();
    expect(
      await screen.findByText("Counting critical findings"),
    ).toBeInTheDocument();
  });

  it("opens a recent chat in place without navigating", async () => {
    // Given
    const user = userEvent.setup();
    const replaceStateSpy = vi.spyOn(window.history, "replaceState");
    getSessionsMock.mockResolvedValue({
      data: [session("session-1", "Counting critical findings")],
    });
    getMessagesMock.mockResolvedValue({
      data: [
        {
          id: "message-1",
          role: "assistant",
          model: null,
          tokenUsage: null,
          insertedAt: "2026-06-25T10:00:00Z",
          parts: [
            {
              id: "message-1-part",
              type: "text",
              content: "There are 3 critical findings.",
              toolCallOutcome: null,
              insertedAt: "2026-06-25T10:00:00Z",
              updatedAt: "2026-06-25T10:00:00Z",
            },
          ],
        },
      ],
    });
    render(<LighthousePanelChat />);

    // When
    await user.click(
      await screen.findByRole("button", {
        name: /^Counting critical findings/,
      }),
    );

    // Then: the conversation loads in the panel and the URL never changes
    expect(
      await screen.findByText("There are 3 critical findings."),
    ).toBeInTheDocument();
    expect(replaceStateSpy).not.toHaveBeenCalled();
    replaceStateSpy.mockRestore();
  });

  it("explains why a new chat is unavailable before the first message", async () => {
    // Given
    const user = userEvent.setup();
    render(<LighthousePanelHeaderActions />);
    const newChatButton = screen.getByRole("button", { name: "New chat" });

    // When
    const disabledTrigger = newChatButton.parentElement;

    // Then
    expect(newChatButton).toBeDisabled();
    expect(disabledTrigger).toHaveClass("cursor-not-allowed");
    await user.hover(disabledTrigger!);
    expect(await screen.findByRole("tooltip")).toHaveTextContent(
      "Send a message before starting a new chat",
    );
  });

  it("opens the active panel conversation on the full-page chat route", async () => {
    // Given: the panel starts on a new chat and exposes the full-page action
    const user = userEvent.setup();
    getSessionsMock.mockResolvedValue({
      data: [session("session-1", "Counting critical findings")],
    });
    render(
      <>
        <LighthousePanelHeaderActions />
        <LighthousePanelChat />
      </>,
    );
    const fullPageLink = await screen.findByRole("link", {
      name: "Open Lighthouse AI full page",
    });
    expect(fullPageLink).toHaveAttribute("href", "/lighthouse");

    // When: an existing conversation becomes active in the panel
    await user.click(
      await screen.findByRole("button", {
        name: /^Counting critical findings/,
      }),
    );

    // Then: full-page navigation carries the active session in the URL
    expect(fullPageLink).toHaveAttribute(
      "href",
      "/lighthouse?session=session-1",
    );
  });

  it("starts a new chat from the panel header", async () => {
    // Given: an existing conversation is open in the panel
    const user = userEvent.setup();
    getSessionsMock.mockResolvedValue({
      data: [session("session-1", "Counting critical findings")],
    });
    getMessagesMock.mockResolvedValue({
      data: [
        {
          id: "message-1",
          role: "assistant",
          model: null,
          tokenUsage: null,
          insertedAt: "2026-06-25T10:00:00Z",
          parts: [
            {
              id: "message-1-part",
              type: "text",
              content: "There are 3 critical findings.",
              toolCallOutcome: null,
              insertedAt: "2026-06-25T10:00:00Z",
              updatedAt: "2026-06-25T10:00:00Z",
            },
          ],
        },
      ],
    });
    render(
      <>
        <div aria-label="Panel header actions">
          <LighthousePanelHeaderActions />
        </div>
        <LighthousePanelChat />
      </>,
    );
    await screen.findByRole("textbox", { name: "Message" });
    const panelHeader = screen.getByLabelText("Panel header actions");
    const newChatButton = within(panelHeader).getByRole("button", {
      name: "New chat",
    });
    expect(newChatButton).toBeDisabled();

    await user.click(
      await screen.findByRole("button", {
        name: /^Counting critical findings/,
      }),
    );
    expect(
      await screen.findByText("There are 3 critical findings."),
    ).toBeInTheDocument();
    expect(newChatButton).toBeEnabled();

    // When
    await user.click(newChatButton);

    // Then
    expect(
      screen.queryByText("There are 3 critical findings."),
    ).not.toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: "Message" })).toHaveValue("");
    expect(newChatButton).toBeDisabled();
  });

  it("caches the loaded config so a remount skips the skeleton", async () => {
    // Given: a first mount that loads successfully
    const { unmount } = render(<LighthousePanelChat />);
    await screen.findByRole("textbox", { name: "Message" });
    unmount();
    getConfigurationsMock.mockClear();

    // When
    render(<LighthousePanelChat />);

    // Then: ready immediately, no refetch
    await waitFor(() =>
      expect(
        screen.getByRole("textbox", { name: "Message" }),
      ).toBeInTheDocument(),
    );
    expect(getConfigurationsMock).not.toHaveBeenCalled();
  });

  it("reloads models after a transient model-loading failure", async () => {
    // Given: configuration loads, but the first model request fails
    getSupportedModelsMock.mockResolvedValueOnce({
      error: "Models are temporarily unavailable.",
      status: 500,
    });
    const { unmount } = render(<LighthousePanelChat />);
    await screen.findByRole("textbox", { name: "Message" });
    unmount();
    getSupportedModelsMock.mockClear();

    // When: the panel reopens after the model endpoint recovers
    render(<LighthousePanelChat />);

    // Then: the partial ready state is not reused as a successful cache entry
    await waitFor(() => expect(getSupportedModelsMock).toHaveBeenCalled());
  });

  it("removes an archived chat from the recent chats list", async () => {
    // Given: one recent chat
    const user = userEvent.setup();
    getSessionsMock.mockResolvedValue({
      data: [session("session-1", "Counting critical findings")],
    });
    archiveSessionMock.mockResolvedValue({ data: { id: "session-1" } });
    render(<LighthousePanelChat />);
    await screen.findByText("Counting critical findings");

    // When: archiving it from the panel (hover action + confirm dialog)
    getSessionsMock.mockResolvedValue({ data: [] });
    await user.click(
      screen.getByRole("button", {
        name: "Archive Counting critical findings",
      }),
    );
    await user.click(
      within(await screen.findByRole("dialog")).getByRole("button", {
        name: "Archive",
      }),
    );

    // Then: the archived chat leaves the list
    await waitFor(() =>
      expect(
        screen.queryByText("Counting critical findings"),
      ).not.toBeInTheDocument(),
    );
  });

  it("swaps the connect CTA for the chat once a provider is connected", async () => {
    // Given: no connected provider yet
    getConfigurationsMock.mockResolvedValueOnce({
      data: [{ ...configurations[0], connected: false }],
    });
    render(<LighthousePanelChat />);
    await screen.findByRole("link", { name: "Connect an LLM provider" });

    // When: a provider gets connected on the settings page
    act(() => notifyLighthouseV2ConfigurationsChanged());

    // Then: the panel reloads into the live chat
    expect(
      await screen.findByRole("textbox", { name: "Message" }),
    ).toBeInTheDocument();
  });

  it("drops the cached config when configurations change while unmounted", async () => {
    // Given: a cached config from a previous mount
    const { unmount } = render(<LighthousePanelChat />);
    await screen.findByRole("textbox", { name: "Message" });
    unmount();
    getConfigurationsMock.mockClear();

    // When: config CRUD happens with the panel closed, then it reopens
    notifyLighthouseV2ConfigurationsChanged();
    render(<LighthousePanelChat />);

    // Then: the stale cache is gone and the config reloads
    expect(
      await screen.findByRole("textbox", { name: "Message" }),
    ).toBeInTheDocument();
    expect(getConfigurationsMock).toHaveBeenCalled();
  });
});

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

function session(id: string, title: string): LighthouseV2Session {
  return {
    id,
    title,
    isArchived: false,
    insertedAt: "2026-06-24T10:00:00Z",
    updatedAt: "2026-06-24T10:00:00Z",
  };
}
