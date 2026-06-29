import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { LighthouseV2BusinessContextForm } from "./business-context-form";

const { updateTenantConfigurationMock } = vi.hoisted(() => ({
  updateTenantConfigurationMock: vi.fn(),
}));

vi.mock("@/app/(prowler)/lighthouse/_actions", () => ({
  updateLighthouseV2TenantConfiguration: updateTenantConfigurationMock,
}));

function tenantConfig(businessContext: string) {
  return {
    id: "tenant-config-1",
    businessContext,
    defaultProvider: "" as const,
    defaultModels: {},
  };
}

describe("LighthouseV2BusinessContextForm", () => {
  beforeEach(() => {
    updateTenantConfigurationMock.mockReset();
    updateTenantConfigurationMock.mockResolvedValue({
      data: tenantConfig("Production context"),
    });
  });

  it("seeds the textarea with the tenant business context and disables save until edited", () => {
    // Given / When
    render(
      <LighthouseV2BusinessContextForm initialBusinessContext="Production context" />,
    );

    // Then
    expect(
      screen.getByRole("textbox", { name: /Business context/i }),
    ).toHaveValue("Production context");
    expect(
      screen.getByRole("button", { name: "Save business context" }),
    ).toBeDisabled();
  });

  it("saves the shared business context to the tenant configuration", async () => {
    // Given
    const user = userEvent.setup();
    render(<LighthouseV2BusinessContextForm initialBusinessContext="" />);

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
      expect(updateTenantConfigurationMock).toHaveBeenCalledWith({
        businessContext: "Production context",
      }),
    );
  });

  it("shows the counter and blocks saving over the character limit", async () => {
    // Given
    const user = userEvent.setup();
    render(<LighthouseV2BusinessContextForm initialBusinessContext="" />);

    // When: paste in one event instead of 1001 keystrokes
    await user.click(
      screen.getByRole("textbox", { name: /Business context/i }),
    );
    await user.paste("a".repeat(1001));

    // Then
    expect(screen.getByText("1001/1000")).toBeInTheDocument();
    expect(
      screen.getByText("Business context cannot exceed 1000 characters."),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Save business context" }),
    ).toBeDisabled();
    expect(updateTenantConfigurationMock).not.toHaveBeenCalled();
  });

  it("surfaces the backend reason when the save fails", async () => {
    // Given
    const user = userEvent.setup();
    updateTenantConfigurationMock.mockResolvedValue({
      error: "No active configuration found for 'bedrock'.",
      status: 400,
    });
    render(<LighthouseV2BusinessContextForm initialBusinessContext="" />);

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
