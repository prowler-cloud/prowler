import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ComponentProps } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useProviderWizardStore } from "@/store/provider-wizard/store";
import { SCAN_JOBS_TAB } from "@/types";
import {
  SCAN_SCHEDULE_CAPABILITY,
  SCHEDULE_FREQUENCY,
} from "@/types/schedules";

import { LaunchStep } from "./launch-step";

const { scanOnDemandMock, scheduleDailyMock, toastMock, updateScheduleMock } =
  vi.hoisted(() => ({
    scanOnDemandMock: vi.fn(),
    scheduleDailyMock: vi.fn(),
    toastMock: vi.fn(),
    updateScheduleMock: vi.fn(),
  }));

vi.mock("@/actions/scans", () => ({
  scanOnDemand: scanOnDemandMock,
  scheduleDaily: scheduleDailyMock,
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

const seedConnectedProvider = () => {
  useProviderWizardStore.setState({
    providerId: "provider-1",
    providerType: "gcp",
    providerUid: "project-123",
    mode: "add",
  });
};

const lastFooterConfig = (onFooterChange: ReturnType<typeof vi.fn>) =>
  onFooterChange.mock.calls.at(-1)?.[0];

describe("LaunchStep", () => {
  beforeEach(() => {
    vi.spyOn(Intl, "DateTimeFormat").mockReturnValue({
      resolvedOptions: () => ({ timeZone: "Europe/Madrid" }),
    } as Intl.DateTimeFormat);
    sessionStorage.clear();
    localStorage.clear();
    updateScheduleMock.mockReset();
    scheduleDailyMock.mockReset();
    scanOnDemandMock.mockReset();
    toastMock.mockReset();
    useProviderWizardStore.getState().reset();
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  describe("Prowler OSS (non-Cloud)", () => {
    beforeEach(() => {
      vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");
      scheduleDailyMock.mockResolvedValue({ data: { id: "schedule-1" } });
    });

    it("renders the schedule UI with advanced cadences locked and no timezone field", async () => {
      // Given
      const onFooterChange = vi.fn();
      seedConnectedProvider();

      render(
        <LaunchStep
          onBack={vi.fn()}
          onClose={vi.fn()}
          onFooterChange={onFooterChange}
        />,
      );

      // Then
      expect(screen.getByText("Account Connected!")).toBeInTheDocument();
      expect(
        screen.queryByRole("combobox", { name: /timezone/i }),
      ).not.toBeInTheDocument();
      // Daily is shown but the "Repeats" selector is locked for OSS.
      expect(screen.getByRole("combobox", { name: /repeats/i })).toBeDisabled();

      await waitFor(() => expect(onFooterChange).toHaveBeenCalled());
      expect(lastFooterConfig(onFooterChange)?.actionLabel).toBe("Save");
    });

    it("saves via the legacy daily endpoint and never the new schedule API", async () => {
      // Given
      const onClose = vi.fn();
      const onFooterChange = vi.fn();
      seedConnectedProvider();

      render(
        <LaunchStep
          onBack={vi.fn()}
          onClose={onClose}
          onFooterChange={onFooterChange}
        />,
      );
      await waitFor(() => expect(onFooterChange).toHaveBeenCalled());

      // When
      await act(async () => {
        lastFooterConfig(onFooterChange)?.onAction?.();
      });

      // Then
      await waitFor(() => expect(scheduleDailyMock).toHaveBeenCalledTimes(1));
      const sentFormData = scheduleDailyMock.mock.calls[0]?.[0] as FormData;
      expect(sentFormData.get("providerId")).toBe("provider-1");
      expect(updateScheduleMock).not.toHaveBeenCalled();
      expect(scanOnDemandMock).not.toHaveBeenCalled();
      expect(onClose).toHaveBeenCalledTimes(1);
    });

    it("also launches an on-demand scan when the checkbox is checked", async () => {
      // Given
      const user = userEvent.setup();
      const onFooterChange = vi.fn();
      seedConnectedProvider();
      scanOnDemandMock.mockResolvedValue({ data: { id: "scan-1" } });

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
        screen.getByRole("checkbox", { name: /launch an initial scan now/i }),
      );
      await act(async () => {
        lastFooterConfig(onFooterChange)?.onAction?.();
      });

      // Then
      await waitFor(() => expect(scheduleDailyMock).toHaveBeenCalledTimes(1));
      expect(scanOnDemandMock).toHaveBeenCalledTimes(1);
      expect(updateScheduleMock).not.toHaveBeenCalled();
    });
  });

  describe("Prowler Cloud subscribed", () => {
    beforeEach(() => {
      vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");
      updateScheduleMock.mockResolvedValue({ data: { id: "provider-1" } });
    });

    it("enables advanced cadences and saves through the new schedule API", async () => {
      // Given
      const onClose = vi.fn();
      const onFooterChange = vi.fn();
      seedConnectedProvider();

      render(
        <LaunchStep
          onBack={vi.fn()}
          onClose={onClose}
          onFooterChange={onFooterChange}
        />,
      );

      // Then advanced cadence selector is enabled
      expect(
        screen.getByRole("combobox", { name: /repeats/i }),
      ).not.toBeDisabled();
      await waitFor(() => expect(onFooterChange).toHaveBeenCalled());

      // When
      await act(async () => {
        lastFooterConfig(onFooterChange)?.onAction?.();
      });

      // Then
      await waitFor(() => expect(updateScheduleMock).toHaveBeenCalledTimes(1));
      expect(updateScheduleMock).toHaveBeenCalledWith(
        "provider-1",
        expect.objectContaining({
          scan_enabled: true,
          scan_frequency: SCHEDULE_FREQUENCY.DAILY,
          scan_hour: expect.any(Number),
          scan_timezone: "Europe/Madrid",
          scan_day_of_week: null,
          scan_day_of_month: null,
        }),
      );
      expect(scheduleDailyMock).not.toHaveBeenCalled();
      expect(scanOnDemandMock).not.toHaveBeenCalled();
      expect(onClose).toHaveBeenCalledTimes(1);
      const toastPayload = toastMock.mock.calls[0]?.[0];
      expect(toastPayload.action.props.children.props.href).toBe(
        `/scans?tab=${SCAN_JOBS_TAB.ACTIVE}`,
      );
    });

    it("also launches an on-demand scan when the checkbox is checked", async () => {
      // Given
      const user = userEvent.setup();
      const onFooterChange = vi.fn();
      seedConnectedProvider();
      scanOnDemandMock.mockResolvedValue({ data: { id: "scan-1" } });

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
        screen.getByRole("checkbox", { name: /launch an initial scan now/i }),
      );
      await act(async () => {
        lastFooterConfig(onFooterChange)?.onAction?.();
      });

      // Then
      await waitFor(() => expect(updateScheduleMock).toHaveBeenCalledTimes(1));
      expect(scanOnDemandMock).toHaveBeenCalledTimes(1);
      expect(scheduleDailyMock).not.toHaveBeenCalled();
    });

    it("does not launch an initial scan when the schedule save fails", async () => {
      // Given
      const user = userEvent.setup();
      const onFooterChange = vi.fn();
      seedConnectedProvider();
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
        screen.getByRole("checkbox", { name: /launch an initial scan now/i }),
      );
      await act(async () => {
        lastFooterConfig(onFooterChange)?.onAction?.();
      });

      // Then
      await waitFor(() => expect(updateScheduleMock).toHaveBeenCalledTimes(1));
      expect(scanOnDemandMock).not.toHaveBeenCalled();
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Unable to save scan schedule" }),
      );
    });
  });

  describe("Prowler Cloud trial/onboarding (manual scan only)", () => {
    beforeEach(() => {
      vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");
      scanOnDemandMock.mockResolvedValue({ data: { id: "scan-1" } });
    });

    it("hides scheduling and only launches a manual scan", async () => {
      // Given
      const onClose = vi.fn();
      const onFooterChange = vi.fn();
      seedConnectedProvider();

      render(
        <LaunchStep
          onBack={vi.fn()}
          onClose={onClose}
          onFooterChange={onFooterChange}
          capability={SCAN_SCHEDULE_CAPABILITY.MANUAL_ONLY}
        />,
      );

      // Then no schedule cadence selector is rendered
      expect(
        screen.queryByRole("combobox", { name: /repeats/i }),
      ).not.toBeInTheDocument();
      await waitFor(() => expect(onFooterChange).toHaveBeenCalled());
      expect(lastFooterConfig(onFooterChange)?.actionDisabled).toBe(false);
      // The action launches a scan here, so it must not be labeled "Save".
      expect(lastFooterConfig(onFooterChange)?.actionLabel).toBe("Launch scan");

      // When
      await act(async () => {
        lastFooterConfig(onFooterChange)?.onAction?.();
      });

      // Then
      await waitFor(() => expect(scanOnDemandMock).toHaveBeenCalledTimes(1));
      expect(updateScheduleMock).not.toHaveBeenCalled();
      expect(scheduleDailyMock).not.toHaveBeenCalled();
      expect(onClose).toHaveBeenCalledTimes(1);
    });

    it("disables the action and shows the limit copy when over limit", async () => {
      // Given
      const onFooterChange = vi.fn();
      seedConnectedProvider();

      render(
        <LaunchStep
          onBack={vi.fn()}
          onClose={vi.fn()}
          onFooterChange={onFooterChange}
          capability={SCAN_SCHEDULE_CAPABILITY.MANUAL_ONLY}
          isScanLimitReached
        />,
      );

      // Then
      expect(screen.getByText(/reached your scan limit/i)).toBeInTheDocument();
      await waitFor(() => expect(onFooterChange).toHaveBeenCalled());
      expect(lastFooterConfig(onFooterChange)?.actionDisabled).toBe(true);
    });
  });
});
