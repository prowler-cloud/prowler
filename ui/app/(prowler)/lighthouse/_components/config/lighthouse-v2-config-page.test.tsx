import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type {
  LighthouseV2Configuration,
  LighthouseV2SupportedProvider,
} from "@/app/(prowler)/lighthouse/_types";

import { LighthouseV2ConfigPage } from "./lighthouse-v2-config-page";

const {
  createConfigurationMock,
  deleteConfigurationMock,
  testConnectionMock,
  updateConfigurationMock,
  toastMock,
} = vi.hoisted(() => ({
  createConfigurationMock: vi.fn(),
  deleteConfigurationMock: vi.fn(),
  testConnectionMock: vi.fn(),
  updateConfigurationMock: vi.fn(),
  toastMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: vi.fn(), push: vi.fn() }),
}));

// Action feedback is delivered through toasts (rendered by the layout Toaster),
// so we assert the dispatched toast rather than in-page banner text.
vi.mock("@/components/shadcn", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  useToast: () => ({ toast: toastMock, dismiss: vi.fn() }),
}));

vi.mock("@/app/(prowler)/lighthouse/_actions", () => ({
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

const configurations: LighthouseV2Configuration[] = [
  {
    id: "config-openai",
    providerType: "openai",
    baseUrl: null,
    defaultModel: "gpt-5.1",
    businessContext: "Production context",
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
    businessContext: "Production context",
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
    testConnectionMock.mockReset();
    updateConfigurationMock.mockReset();
    toastMock.mockReset();

    createConfigurationMock.mockResolvedValue({ data: configurations[0] });
    deleteConfigurationMock.mockResolvedValue({ data: true });
    // The action polls the task internally and resolves with the re-fetched
    // configuration carrying the authoritative connection status.
    testConnectionMock.mockResolvedValue({
      data: { ...configurations[0], connected: true },
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
      name: "Lighthouse AI settings",
    });
    const settingsSeparator = container.querySelector(
      '[data-slot="settings-separator"]',
    );
    const innerCards = settingsCard.querySelectorAll('[data-slot="card"]');

    expect(settingsCard).toHaveAttribute("data-slot", "card");
    expect(settingsCard).toHaveClass("w-full", "gap-4", "p-4", "md:p-5");
    expect(settingsCard).not.toHaveClass(
      "gap-0",
      "overflow-hidden",
      "mx-auto",
      "max-w-7xl",
    );
    expect(settingsSeparator).toBeNull();
    expect(innerCards).toHaveLength(3);
    innerCards.forEach((card) =>
      expect(card).toHaveClass(
        "border-border-neutral-tertiary",
        "bg-bg-neutral-tertiary",
      ),
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

  it("renders a single shared business context, not a per-provider default model", async () => {
    // Given
    const user = userEvent.setup();
    renderPage();

    // Then: business context is tenant-wide, so there is exactly one editor
    expect(
      screen.getAllByRole("textbox", { name: /Business context/i }),
    ).toHaveLength(1);

    // When switching providers, no per-provider model/context field appears
    await user.click(screen.getByRole("button", { name: /Amazon Bedrock/i }));

    // Then
    expect(
      screen.queryByRole("combobox", { name: "Default model" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText("Default model")).not.toBeInTheDocument();
    expect(
      screen.getAllByRole("textbox", { name: /Business context/i }),
    ).toHaveLength(1);
  });

  it("hides the business context editor until a provider is configured", () => {
    // Given / When: no configurations exist yet
    renderPage({ configurations: [] });

    // Then: the editor is replaced by a hint and the textarea is absent
    expect(
      screen.queryByRole("textbox", { name: /Business context/i }),
    ).not.toBeInTheDocument();
    expect(screen.getByText(/Configure a provider first/i)).toBeInTheDocument();
  });

  it("updates an existing configuration without sending blank credentials or model defaults", async () => {
    // Given
    const user = userEvent.setup();
    updateConfigurationMock.mockResolvedValue({ data: configurations[0] });
    renderPage();

    // When: save the active provider without touching credentials
    await user.click(
      within(
        screen.getByRole("region", { name: "Lighthouse AI settings" }),
      ).getByRole("button", { name: /^Save$/i }),
    );

    // Then
    await waitFor(() => expect(updateConfigurationMock).toHaveBeenCalled());
    expect(updateConfigurationMock.mock.calls[0]?.[0]).toBe("config-openai");
    expect(updateConfigurationMock.mock.calls[0]?.[1]).not.toHaveProperty(
      "credentials",
    );
    expect(updateConfigurationMock.mock.calls[0]?.[1]).not.toHaveProperty(
      "defaultModel",
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
      businessContext: "",
      connected: null,
      connectionLastCheckedAt: null,
      insertedAt: "2026-06-24T10:00:00Z",
      updatedAt: "2026-06-24T10:00:00Z",
    };
    createConfigurationMock.mockResolvedValue({ data: createdConfig });
    testConnectionMock.mockResolvedValue({
      data: {
        ...createdConfig,
        connected: true,
        connectionLastCheckedAt: "2026-06-24T10:01:00Z",
      },
    });
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
    await user.click(screen.getByRole("button", { name: /^Save$/i }));

    // Then
    await waitFor(() => expect(createConfigurationMock).toHaveBeenCalled());
    expect(createConfigurationMock.mock.calls[0]?.[0]).toEqual(
      expect.objectContaining({
        providerType: "openai-compatible",
        credentials: { api_key: "provider-key" },
        baseUrl: "https://llm.example.com/v1",
      }),
    );
    expect(createConfigurationMock.mock.calls[0]?.[0]).not.toHaveProperty(
      "defaultModel",
    );
    expect(createConfigurationMock.mock.calls[0]?.[0]).not.toHaveProperty(
      "businessContext",
    );
    await waitFor(() =>
      expect(testConnectionMock).toHaveBeenCalledWith("config-compatible"),
    );
    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Connection successful." }),
      ),
    );
    expect(
      within(
        screen.getByRole("button", { name: /OpenAI-compatible/i }),
      ).getByText("Connected"),
    ).toBeInTheDocument();
  });

  it("hints at stored credentials with a masked placeholder", async () => {
    // Given / When: OpenAI and Bedrock already have stored configurations
    const user = userEvent.setup();
    renderPage();

    // Then: secret fields simulate the hidden stored key instead of looking
    // empty, at a length resembling a real API key
    const maskedKey = "•".repeat(36);
    expect(screen.getByLabelText("API key")).toHaveAttribute(
      "placeholder",
      maskedKey,
    );

    await user.click(screen.getByRole("button", { name: /Amazon Bedrock/i }));
    expect(screen.getByLabelText("AWS access key ID")).toHaveAttribute(
      "placeholder",
      maskedKey,
    );
    expect(screen.getByLabelText("AWS secret access key")).toHaveAttribute(
      "placeholder",
      maskedKey,
    );
  });

  it("shows no masked placeholder before credentials are stored", async () => {
    // Given
    const user = userEvent.setup();
    renderPage();

    // When: OpenAI-compatible has no configuration yet
    await user.click(
      screen.getByRole("button", { name: /OpenAI-compatible/i }),
    );

    // Then
    expect(screen.getByLabelText("API key")).not.toHaveAttribute("placeholder");
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

  it("tests the connection and reports the resulting status", async () => {
    // Given
    const user = userEvent.setup();
    testConnectionMock.mockResolvedValue({
      data: { ...configurations[0], connected: false },
    });
    renderPage();

    // When
    await user.click(screen.getByRole("button", { name: /Test connection/i }));

    // Then: the action is polled to completion and the resulting status shown
    await waitFor(() =>
      expect(testConnectionMock).toHaveBeenCalledWith("config-openai"),
    );
    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({
          title: "Connection failed.",
          variant: "destructive",
        }),
      ),
    );
    expect(
      screen.queryByRole("button", { name: /Refresh status/i }),
    ).not.toBeInTheDocument();
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
    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Configuration removed." }),
      ),
    );
  });
});

function renderPage(
  props?: Partial<Parameters<typeof LighthouseV2ConfigPage>[0]>,
) {
  return render(
    <LighthouseV2ConfigPage
      configurations={props?.configurations ?? configurations}
      providers={props?.providers ?? providers}
      error={props?.error}
    />,
  );
}
