import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ComponentProps } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useProviderWizardStore } from "@/store/provider-wizard/store";
import { SCAN_JOBS_TAB } from "@/types";
import { SCHEDULE_FREQUENCY } from "@/types/schedules";

import { LaunchStep } from "./launch-step";

const { scanOnDemandMock, toastMock, updateScheduleMock } = vi.hoisted(() => ({
  scanOnDemandMock: vi.fn(),
  toastMock: vi.fn(),
  updateScheduleMock: vi.fn(),
}));

vi.mock("@/actions/scans", () => ({
  scanOnDemand: scanOnDemandMock,
}));

vi.mock("@/actions/schedules", () => ({
  updateSchedule: updateScheduleMock,
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
    updateScheduleMock.mockReset();
    scanOnDemandMock.mockReset();
    toastMock.mockReset();
    useProviderWizardStore.getState().reset();
  });

  it("saves a schedule without launching an initial scan", async () => {
    // Given
    const onClose = vi.fn();
    const onFooterChange = vi.fn();
    useProviderWizardStore.setState({
      providerId: "provider-1",
      providerType: "gcp",
      providerUid: "project-123",
      mode: "add",
    });

    updateScheduleMock.mockResolvedValue({ data: { id: "provider-1" } });

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
      expect(updateScheduleMock).toHaveBeenCalledTimes(1);
    });

    expect(updateScheduleMock).toHaveBeenCalledWith(
      "provider-1",
      expect.objectContaining({
        scan_enabled: true,
        scan_frequency: SCHEDULE_FREQUENCY.DAILY,
        scan_hour: expect.any(Number),
      }),
    );
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(scanOnDemandMock).not.toHaveBeenCalled();
    expect(toastMock).toHaveBeenCalledWith(
      expect.objectContaining({
        title: "Scan schedule saved",
      }),
    );
    const toastPayload = toastMock.mock.calls[0]?.[0];
    expect(toastPayload.action.props.children.props.href).toBe(
      `/scans?tab=${SCAN_JOBS_TAB.ACTIVE}`,
    );
  });

  it("launches an initial scan after schedule save when checkbox is checked", async () => {
    // Given
    const user = userEvent.setup();
    const onClose = vi.fn();
    const onFooterChange = vi.fn();
    useProviderWizardStore.setState({
      providerId: "provider-1",
      providerType: "gcp",
      providerUid: "project-123",
      mode: "add",
    });

    updateScheduleMock.mockResolvedValue({ data: { id: "provider-1" } });
    scanOnDemandMock.mockResolvedValue({ data: { id: "scan-1" } });

    render(
      <LaunchStep
        onBack={vi.fn()}
        onClose={onClose}
        onFooterChange={onFooterChange}
      />,
    );
    await waitFor(() => expect(onFooterChange).toHaveBeenCalled());

    // When
    await user.click(
      screen.getByRole("checkbox", {
        name: /launch an initial scan now/i,
      }),
    );
    const footerConfig = onFooterChange.mock.calls.at(-1)?.[0];
    await act(async () => {
      footerConfig.onAction?.();
    });

    // Then
    await waitFor(() => expect(updateScheduleMock).toHaveBeenCalledTimes(1));
    expect(scanOnDemandMock).toHaveBeenCalledTimes(1);
    const sentFormData = scanOnDemandMock.mock.calls[0]?.[0] as FormData;
    expect(sentFormData.get("providerId")).toBe("provider-1");
    expect(toastMock).toHaveBeenCalledWith(
      expect.objectContaining({
        title: "Scan schedule saved and initial scan launched",
      }),
    );
  });

  it("does not launch an initial scan when schedule save fails", async () => {
    // Given
    const user = userEvent.setup();
    const onFooterChange = vi.fn();
    useProviderWizardStore.setState({
      providerId: "provider-1",
      providerType: "gcp",
      providerUid: "project-123",
      mode: "add",
    });

    updateScheduleMock.mockResolvedValue({ error: "Schedule failed" });

    render(
      <LaunchStep
        onBack={vi.fn()}
        onClose={vi.fn()}
        onFooterChange={onFooterChange}
      />,
    );
    await waitFor(() => expect(onFooterChange).toHaveBeenCalled());

    // When
    await user.click(
      screen.getByRole("checkbox", {
        name: /launch an initial scan now/i,
      }),
    );
    const footerConfig = onFooterChange.mock.calls.at(-1)?.[0];
    await act(async () => {
      footerConfig.onAction?.();
    });

    // Then
    await waitFor(() => expect(updateScheduleMock).toHaveBeenCalledTimes(1));
    expect(scanOnDemandMock).not.toHaveBeenCalled();
    expect(toastMock).toHaveBeenCalledWith(
      expect.objectContaining({
        title: "Unable to save scan schedule",
      }),
    );
  });
});
