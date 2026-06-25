import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type {
  LighthouseV2Configuration,
  LighthouseV2SupportedModel,
  LighthouseV2SupportedProvider,
} from "@/types/lighthouse-v2";

import { LighthouseV2ConfigPage } from "./lighthouse-v2-config-page";

const {
  createConfigurationMock,
  deleteConfigurationMock,
  refreshMock,
  testConnectionMock,
  updateConfigurationMock,
} = vi.hoisted(() => ({
  createConfigurationMock: vi.fn(),
  deleteConfigurationMock: vi.fn(),
  refreshMock: vi.fn(),
  testConnectionMock: vi.fn(),
  updateConfigurationMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({
    refresh: refreshMock,
  }),
}));

vi.mock("@/actions/lighthouse-v2/lighthouse-v2", () => ({
  createLighthouseV2Configuration: createConfigurationMock,
  deleteLighthouseV2Configuration: deleteConfigurationMock,
  testLighthouseV2ConfigurationConnection: testConnectionMock,
  updateLighthouseV2Configuration: updateConfigurationMock,
}));

const providers: LighthouseV2SupportedProvider[] = [
  { id: "openai", name: "OpenAI" },
  { id: "bedrock", name: "Amazon Bedrock" },
  { id: "openai-compatible", name: "OpenAI-compatible" },
];

const modelsByProvider = {
  openai: [
    model("gpt-5.1", {
      supportsFunctionCalling: true,
      supportsVision: true,
      supportsReasoning: true,
    }),
  ],
  bedrock: [
    model("anthropic.claude-4", {
      supportsFunctionCalling: true,
      supportsVision: false,
      supportsReasoning: true,
    }),
  ],
  "openai-compatible": [model("llama-3.3")],
};

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
    connected: false,
    connectionLastCheckedAt: "2026-06-23T10:00:00Z",
    insertedAt: "2026-06-23T09:00:00Z",
    updatedAt: "2026-06-23T10:00:00Z",
  },
];

describe("LighthouseV2ConfigPage", () => {
  beforeEach(() => {
    createConfigurationMock.mockReset();
    deleteConfigurationMock.mockReset();
    refreshMock.mockReset();
    testConnectionMock.mockReset();
    updateConfigurationMock.mockReset();

    createConfigurationMock.mockResolvedValue({ data: configurations[0] });
    deleteConfigurationMock.mockResolvedValue({ data: true });
    testConnectionMock.mockResolvedValue({
      data: {
        id: "task-1",
        name: "lighthouse-config-connection",
        state: "PENDING",
        insertedAt: "2026-06-24T10:01:00Z",
        completedAt: null,
      },
    });
    updateConfigurationMock.mockResolvedValue({ data: configurations[0] });
  });

  it("renders provider statuses and the active provider without the readiness summary card", () => {
    // Given / When
    const { container } = renderPage();

    // Then
    expect(
      screen.queryByRole("heading", { name: "Lighthouse readiness" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText("1 connected")).not.toBeInTheDocument();
    expect(screen.queryByText("1 failed")).not.toBeInTheDocument();
    expect(screen.queryByText("1 not tested")).not.toBeInTheDocument();

    const openAIProvider = screen.getByRole("button", { name: "OpenAI" });
    const settingsCard = screen.getByRole("region", {
      name: "Lighthouse settings",
    });
    const settingsSeparator = container.querySelector(
      '[data-slot="settings-separator"]',
    );

    expect(settingsCard).toHaveAttribute("data-slot", "card");
    expect(settingsCard).toHaveClass(
      "min-h-[calc(100dvh-6.5rem)]",
      "w-full",
      "gap-0",
      "overflow-hidden",
    );
    expect(settingsCard).not.toHaveClass("mx-auto", "max-w-7xl");
    expect(settingsSeparator).toHaveClass(
      "border-t",
      "xl:border-t-0",
      "xl:border-l",
    );
    expect(settingsCard).toContainElement(openAIProvider);
    expect(openAIProvider).toHaveAttribute("aria-pressed", "true");
    expect(within(openAIProvider).getByText("Connected")).toBeInTheDocument();

    const bedrockProvider = screen.getByRole("button", {
      name: /Amazon Bedrock/i,
    });
    expect(within(bedrockProvider).getByText("Failed")).toBeInTheDocument();

    const compatibleProvider = screen.getByRole("button", {
      name: /OpenAI-compatible/i,
    });
    expect(
      within(compatibleProvider).getByText("Not tested"),
    ).toBeInTheDocument();
  });

  it("loads provider-specific form values when switching provider", async () => {
    // Given
    const user = userEvent.setup();
    renderPage();

    // When
    await user.click(screen.getByRole("button", { name: /Amazon Bedrock/i }));

    // Then
    expect(
      screen.getByRole("textbox", { name: /Business context/i }),
    ).toHaveValue("AWS landing zone");
    expect(
      screen.getByRole("combobox", { name: "Default model" }),
    ).toHaveTextContent("anthropic.claude-4");
  });

  it("updates an existing configuration without sending blank credentials", async () => {
    // Given
    const user = userEvent.setup();
    updateConfigurationMock.mockResolvedValue({
      data: {
        ...configurations[0],
        businessContext: "Updated context",
      },
    });
    renderPage();

    // When
    await user.clear(
      screen.getByRole("textbox", { name: /Business context/i }),
    );
    await user.type(
      screen.getByRole("textbox", { name: /Business context/i }),
      "Updated context",
    );
    await user.click(screen.getByRole("button", { name: /^Save$/i }));

    // Then
    await waitFor(() =>
      expect(updateConfigurationMock).toHaveBeenCalledWith(
        "config-openai",
        expect.not.objectContaining({ credentials: expect.anything() }),
      ),
    );
  });

  it("creates a new OpenAI-compatible configuration with required credentials", async () => {
    // Given
    const user = userEvent.setup();
    const createdConfig: LighthouseV2Configuration = {
      id: "config-compatible",
      providerType: "openai-compatible",
      baseUrl: "https://llm.example.com/v1",
      defaultModel: "llama-3.3",
      businessContext: "Private model",
      connected: null,
      connectionLastCheckedAt: null,
      insertedAt: "2026-06-24T10:00:00Z",
      updatedAt: "2026-06-24T10:00:00Z",
    };
    createConfigurationMock.mockResolvedValue({ data: createdConfig });
    renderPage();

    // When
    await user.click(
      screen.getByRole("button", { name: /OpenAI-compatible/i }),
    );
    await user.type(screen.getByLabelText("API key"), "provider-key");
    await user.type(
      screen.getByLabelText("Base URL"),
      "https://llm.example.com/v1",
    );
    await user.type(
      screen.getByRole("textbox", { name: /Business context/i }),
      "Private model",
    );
    await user.click(screen.getByRole("button", { name: /^Save$/i }));

    // Then
    await waitFor(() =>
      expect(createConfigurationMock).toHaveBeenCalledWith({
        providerType: "openai-compatible",
        credentials: { api_key: "provider-key" },
        baseUrl: "https://llm.example.com/v1",
        defaultModel: null,
        businessContext: "Private model",
      }),
    );
  });

  it("blocks OpenAI-compatible save when base URL is missing", async () => {
    // Given
    const user = userEvent.setup();
    renderPage();

    // When
    await user.click(
      screen.getByRole("button", { name: /OpenAI-compatible/i }),
    );
    await user.type(screen.getByLabelText("API key"), "provider-key");
    await user.click(screen.getByRole("button", { name: /^Save$/i }));

    // Then
    expect(
      await screen.findByText(
        "Base URL is required for OpenAI-compatible providers.",
      ),
    ).toBeInTheDocument();
    expect(createConfigurationMock).not.toHaveBeenCalled();
  });

  it("shows Bedrock access key, secret key, and region fields", async () => {
    // Given
    const user = userEvent.setup();
    renderPage();

    // When
    await user.click(screen.getByRole("button", { name: /Amazon Bedrock/i }));

    // Then
    expect(screen.getByLabelText("AWS access key ID")).toBeInTheDocument();
    expect(screen.getByLabelText("AWS secret access key")).toBeInTheDocument();
    expect(screen.getByLabelText("AWS region")).toBeInTheDocument();
  });

  it("shows the business context counter and blocks values over 1000 characters", async () => {
    // Given
    const user = userEvent.setup();
    renderPage();

    // When
    const businessContext = screen.getByRole("textbox", {
      name: /Business context/i,
    });
    await user.clear(businessContext);
    await user.type(businessContext, "a".repeat(1001));
    await user.click(screen.getByRole("button", { name: /^Save$/i }));

    // Then
    expect(screen.getByText("1001/1000")).toBeInTheDocument();
    expect(
      await screen.findByText(
        "Business context cannot exceed 1000 characters.",
      ),
    ).toBeInTheDocument();
    expect(updateConfigurationMock).not.toHaveBeenCalled();
  });

  it("starts a connection test and exposes a refresh status action", async () => {
    // Given
    const user = userEvent.setup();
    renderPage();

    // When
    await user.click(screen.getByRole("button", { name: /Test connection/i }));

    // Then
    await waitFor(() =>
      expect(testConnectionMock).toHaveBeenCalledWith("config-openai"),
    );
    expect(
      await screen.findByText("Connection check started."),
    ).toBeInTheDocument();

    await user.click(
      screen.getAllByRole("button", { name: /Refresh status/i })[0],
    );
    expect(refreshMock).toHaveBeenCalledTimes(1);
  });

  it("confirms before deleting an existing configuration", async () => {
    // Given
    const user = userEvent.setup();
    renderPage();

    // When
    await user.click(screen.getByRole("button", { name: /^Delete$/i }));
    await user.click(
      screen.getByRole("button", { name: /Delete configuration/i }),
    );

    // Then
    await waitFor(() =>
      expect(deleteConfigurationMock).toHaveBeenCalledWith("config-openai"),
    );
    expect(screen.getByText("Configuration removed.")).toBeInTheDocument();
  });
});

function renderPage(
  props?: Partial<Parameters<typeof LighthouseV2ConfigPage>[0]>,
) {
  return render(
    <LighthouseV2ConfigPage
      configurations={props?.configurations ?? configurations}
      providers={props?.providers ?? providers}
      modelsByProvider={props?.modelsByProvider ?? modelsByProvider}
      error={props?.error}
    />,
  );
}

function model(
  id: string,
  overrides: Partial<LighthouseV2SupportedModel> = {},
): LighthouseV2SupportedModel {
  return {
    id,
    maxInputTokens: null,
    maxOutputTokens: null,
    supportsFunctionCalling: null,
    supportsVision: null,
    supportsReasoning: null,
    ...overrides,
  };
}
