import { act, render, waitFor } from "@testing-library/react";
import type { ComponentProps } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useProviderWizardStore } from "@/store/provider-wizard/store";

import { LaunchStep } from "./launch-step";

const { scheduleDailyMock, scanOnDemandMock, toastMock } = vi.hoisted(() => ({
  scheduleDailyMock: vi.fn(),
  scanOnDemandMock: vi.fn(),
  toastMock: vi.fn(),
}));

vi.mock("@/actions/scans", () => ({
  scheduleDaily: scheduleDailyMock,
  scanOnDemand: scanOnDemandMock,
}));

vi.mock("@/components/ui", () => ({
  ToastAction: ({ children, ...props }: ComponentProps<"button">) => (
    <button {...props}>{children}</button>
  ),
  useToast: () => ({
    toast: toastMock,
  }),
}));

describe("LaunchStep", () => {
  beforeEach(() => {
    sessionStorage.clear();
    localStorage.clear();
    scheduleDailyMock.mockReset();
    scanOnDemandMock.mockReset();
    toastMock.mockReset();
    useProviderWizardStore.getState().reset();
  });

  it("launches a daily scan and shows toast", async () => {
    // Given
    const onClose = vi.fn();
    const onFooterChange = vi.fn();
    useProviderWizardStore.setState({
      providerId: "provider-1",
      providerType: "gcp",
      providerUid: "project-123",
      mode: "add",
    });

    scheduleDailyMock.mockResolvedValue({ data: { id: "scan-1" } });

    render(
      <LaunchStep
        onBack={vi.fn()}
        onClose={onClose}
        onFooterChange={onFooterChange}
      />,
    );

    await waitFor(() => {
      expect(onFooterChange).toHaveBeenCalled();
    });

    // When
    const initialFooterConfig = onFooterChange.mock.calls.at(-1)?.[0];
    await act(async () => {
      initialFooterConfig.onAction?.();
    });

    // Then
    await waitFor(() => {
      expect(scheduleDailyMock).toHaveBeenCalledTimes(1);
    });

    const sentFormData = scheduleDailyMock.mock.calls[0]?.[0] as FormData;
    expect(sentFormData.get("providerId")).toBe("provider-1");
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(scanOnDemandMock).not.toHaveBeenCalled();
    expect(toastMock).toHaveBeenCalledWith(
      expect.objectContaining({
        title: "Scan Launched",
      }),
    );
  });
});
