import { act, render, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useProviderWizardStore } from "@/store/provider-wizard/store";

import { ConnectStep } from "./connect-step";

type ConnectStepUiState = {
  showBack: boolean;
  showAction: boolean;
  actionLabel: string;
  actionDisabled: boolean;
  isLoading: boolean;
};

type CapturedConnectAccountFormProps = {
  onUiStateChange?: (state: ConnectStepUiState) => void;
};

const { capturedConnectAccountFormProps } = vi.hoisted(() => ({
  capturedConnectAccountFormProps: {
    current: null as CapturedConnectAccountFormProps | null,
  },
}));

vi.mock("@/components/providers/workflow/forms", () => ({
  ConnectAccountForm: (props: CapturedConnectAccountFormProps) => {
    capturedConnectAccountFormProps.current = props;

    return <div data-testid="connect-account-form" />;
  },
}));

describe("ConnectStep", () => {
  beforeEach(() => {
    sessionStorage.clear();
    localStorage.clear();
    capturedConnectAccountFormProps.current = null;
    useProviderWizardStore.getState().reset();
  });

  it("does not publish a new footer config when form UI state is unchanged", async () => {
    // Given
    const onFooterChange = vi.fn();

    render(
      <ConnectStep
        onNext={vi.fn()}
        onSelectOrganizations={vi.fn()}
        onFooterChange={onFooterChange}
        onProviderTypeChange={vi.fn()}
      />,
    );

    await waitFor(() => expect(onFooterChange).toHaveBeenCalledTimes(1));

    // When
    act(() => {
      capturedConnectAccountFormProps.current?.onUiStateChange?.({
        showBack: false,
        showAction: false,
        actionLabel: "Next",
        actionDisabled: true,
        isLoading: false,
      });
    });

    // Then
    expect(onFooterChange).toHaveBeenCalledTimes(1);
  });

  it("publishes a new footer config when form UI state changes", async () => {
    // Given
    const onFooterChange = vi.fn();

    render(
      <ConnectStep
        onNext={vi.fn()}
        onSelectOrganizations={vi.fn()}
        onFooterChange={onFooterChange}
        onProviderTypeChange={vi.fn()}
      />,
    );

    await waitFor(() => expect(onFooterChange).toHaveBeenCalledTimes(1));

    // When
    act(() => {
      capturedConnectAccountFormProps.current?.onUiStateChange?.({
        showBack: true,
        showAction: true,
        actionLabel: "Next",
        actionDisabled: false,
        isLoading: false,
      });
    });

    // Then
    await waitFor(() => expect(onFooterChange).toHaveBeenCalledTimes(2));
    expect(onFooterChange.mock.calls.at(-1)?.[0]).toMatchObject({
      showBack: true,
      showAction: true,
      actionDisabled: false,
    });
  });
});
