import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useProviderWizardStore } from "@/store/provider-wizard/store";
import { PROVIDER_WIZARD_MODE } from "@/types/provider-wizard";

import { TestConnectionStep } from "./test-connection-step";

const { getProviderMock } = vi.hoisted(() => ({
  getProviderMock: vi.fn(),
}));

vi.mock("@/actions/providers", () => ({
  getProvider: getProviderMock,
}));

vi.mock("../../workflow/forms/test-connection-form", () => ({
  TestConnectionForm: () => <div data-testid="test-connection-form" />,
}));

describe("TestConnectionStep", () => {
  beforeEach(() => {
    sessionStorage.clear();
    localStorage.clear();
    getProviderMock.mockReset();
    useProviderWizardStore.getState().reset();
  });

  it("stores provider secret id after loading provider data", async () => {
    // Given
    useProviderWizardStore.setState({
      providerId: "provider-1",
      providerType: "aws",
      mode: PROVIDER_WIZARD_MODE.ADD,
    });
    getProviderMock.mockResolvedValue({
      data: {
        id: "provider-1",
        attributes: {
          uid: "111111111111",
          provider: "aws",
          alias: "Production",
          connection: { connected: false, last_checked_at: null },
          scanner_args: {},
        },
        relationships: {
          secret: { data: { type: "provider-secrets", id: "secret-1" } },
        },
      },
    });

    // When
    render(
      <TestConnectionStep
        onSuccess={vi.fn()}
        onResetCredentials={vi.fn()}
        onFooterChange={vi.fn()}
      />,
    );

    // Then
    await waitFor(() => {
      expect(screen.getByTestId("test-connection-form")).toBeInTheDocument();
    });
    expect(useProviderWizardStore.getState().secretId).toBe("secret-1");
  });
});
