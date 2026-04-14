import { render, screen, waitFor } from "@testing-library/react";
import { useEffect } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useProviderWizardStore } from "@/store/provider-wizard/store";
import { PROVIDER_WIZARD_MODE } from "@/types/provider-wizard";

import { TestConnectionStep } from "./test-connection-step";

const { getProviderMock, loadingFromFormMock } = vi.hoisted(() => ({
  getProviderMock: vi.fn(),
  loadingFromFormMock: { current: false },
}));

vi.mock("@/actions/providers", () => ({
  getProvider: getProviderMock,
}));

vi.mock("../../workflow/forms/test-connection-form", () => ({
  TestConnectionForm: ({
    onLoadingChange,
  }: {
    onLoadingChange?: (isLoading: boolean) => void;
  }) => {
    useEffect(() => {
      if (loadingFromFormMock.current) {
        onLoadingChange?.(true);
      }
    }, [onLoadingChange]);

    return <div data-testid="test-connection-form" />;
  },
}));

describe("TestConnectionStep", () => {
  beforeEach(() => {
    sessionStorage.clear();
    localStorage.clear();
    getProviderMock.mockReset();
    loadingFromFormMock.current = false;
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

  it("updates footer action label to checking while connection test is in progress", async () => {
    // Given
    loadingFromFormMock.current = true;
    useProviderWizardStore.setState({
      providerId: "provider-1",
      providerType: "gcp",
      mode: PROVIDER_WIZARD_MODE.ADD,
    });
    getProviderMock.mockResolvedValue({
      data: {
        id: "provider-1",
        attributes: {
          uid: "project-123",
          provider: "gcp",
          alias: "Main",
          connection: { connected: false, last_checked_at: null },
          scanner_args: {},
        },
        relationships: {
          secret: { data: { type: "provider-secrets", id: "secret-1" } },
        },
      },
    });
    const onFooterChange = vi.fn();

    // When
    render(
      <TestConnectionStep
        onSuccess={vi.fn()}
        onResetCredentials={vi.fn()}
        onFooterChange={onFooterChange}
      />,
    );

    // Then
    await waitFor(() => {
      expect(onFooterChange).toHaveBeenCalled();
    });

    await waitFor(() => {
      const footerConfigs = onFooterChange.mock.calls.map((call) => call[0]);
      const hasCheckingState = footerConfigs.some(
        (config) =>
          config.actionLabel === "Checking connection..." &&
          config.actionDisabled === true,
      );
      expect(hasCheckingState).toBe(true);
    });
  });
});
