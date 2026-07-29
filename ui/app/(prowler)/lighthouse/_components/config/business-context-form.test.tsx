import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { LighthouseV2BusinessContextForm } from "./business-context-form";

const { updateConfigurationMock } = vi.hoisted(() => ({
  updateConfigurationMock: vi.fn(),
}));

vi.mock("@/app/(prowler)/lighthouse/_actions", () => ({
  updateLighthouseV2Configuration: updateConfigurationMock,
}));

function configuration(businessContext: string) {
  return {
    id: "config-1",
    providerType: "bedrock" as const,
    baseUrl: null,
    defaultModel: null,
    businessContext,
    connected: true,
    connectionLastCheckedAt: null,
    insertedAt: "2026-06-25T09:00:00Z",
    updatedAt: "2026-06-25T10:00:00Z",
  };
}

describe("LighthouseV2BusinessContextForm", () => {
  beforeEach(() => {
    updateConfigurationMock.mockReset();
    updateConfigurationMock.mockResolvedValue({
      data: configuration("Production context"),
    });
  });

  it("seeds the textarea with the business context and disables save until edited", () => {
    // Given / When
    render(
      <LighthouseV2BusinessContextForm
        configurationId="config-1"
        initialBusinessContext="Production context"
      />,
    );

    // Then
    expect(
      screen.getByRole("textbox", { name: /Business context/i }),
    ).toHaveValue("Production context");
    expect(
      screen.getByRole("button", { name: "Save business context" }),
    ).toBeDisabled();
  });

  it("saves the shared business context against the provider configuration", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <LighthouseV2BusinessContextForm
        configurationId="config-1"
        initialBusinessContext=""
      />,
    );

    // When
    await user.type(
      screen.getByRole("textbox", { name: /Business context/i }),
      "Production context",
    );
    await user.click(
      screen.getByRole("button", { name: "Save business context" }),
    );

    // Then
    await waitFor(() =>
      expect(updateConfigurationMock).toHaveBeenCalledWith("config-1", {
        businessContext: "Production context",
      }),
    );
  });

  it("shows the counter and blocks saving over the character limit", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <LighthouseV2BusinessContextForm
        configurationId="config-1"
        initialBusinessContext=""
      />,
    );

    // When: paste in one event instead of 5001 keystrokes
    await user.click(
      screen.getByRole("textbox", { name: /Business context/i }),
    );
    await user.paste("a".repeat(5001));

    // Then
    expect(screen.getByText("5001/5000")).toBeInTheDocument();
    expect(
      screen.getByText("Business context cannot exceed 5000 characters."),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Save business context" }),
    ).toBeDisabled();
    expect(updateConfigurationMock).not.toHaveBeenCalled();
  });

  it("surfaces the backend reason when the save fails", async () => {
    // Given
    const user = userEvent.setup();
    updateConfigurationMock.mockResolvedValue({
      error: "No active configuration found for 'bedrock'.",
      status: 400,
    });
    render(
      <LighthouseV2BusinessContextForm
        configurationId="config-1"
        initialBusinessContext=""
      />,
    );

    // When
    await user.type(
      screen.getByRole("textbox", { name: /Business context/i }),
      "Production context",
    );
    await user.click(
      screen.getByRole("button", { name: "Save business context" }),
    );

    // Then
    expect(
      await screen.findByText("No active configuration found for 'bedrock'."),
    ).toBeInTheDocument();
  });
});
