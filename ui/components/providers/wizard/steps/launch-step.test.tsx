import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ComponentProps } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  ACTION_ERROR_API_MESSAGES,
  ACTION_ERROR_MESSAGES,
  ACTION_ERROR_STATUS,
} from "@/lib/action-errors";
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

vi.mock("@/components/shadcn", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
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
      scanOnDemandMock.mockResolvedValue({ data: { id: "scan-1" } });
    });

    it("defaults to daily schedule mode and locks advanced cadence outside Cloud", async () => {
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
      expect(screen.getByText("Provider Connected!")).toBeInTheDocument();
      expect(
        screen.getByRole("radio", { name: "On a schedule" }),
      ).toBeChecked();
      expect(screen.getByRole("radio", { name: "Run now" })).not.toBeChecked();
      expect(
        screen.getByRole("radio", { name: "On a schedule" }),
      ).toBeEnabled();
      expect(screen.getByRole("combobox", { name: /repeats/i })).toBeDisabled();

      await waitFor(() => expect(onFooterChange).toHaveBeenCalled());
      expect(lastFooterConfig(onFooterChange)?.actionLabel).toBe("Save");
    });

    it("saves a legacy daily schedule by default", async () => {
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
      expect(scanOnDemandMock).not.toHaveBeenCalled();
      expect(updateScheduleMock).not.toHaveBeenCalled();
      expect(onClose).toHaveBeenCalledTimes(1);
    });

    it("launches only an on-demand scan when run now is selected", async () => {
      // Given
      const user = userEvent.setup();
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
      await user.click(screen.getByRole("radio", { name: "Run now" }));
      await waitFor(() =>
        expect(lastFooterConfig(onFooterChange)?.actionLabel).toBe(
          "Launch scan",
        ),
      );
      await act(async () => {
        lastFooterConfig(onFooterChange)?.onAction?.();
      });

      // Then
      await waitFor(() => expect(scanOnDemandMock).toHaveBeenCalledTimes(1));
      expect(scheduleDailyMock).not.toHaveBeenCalled();
      expect(updateScheduleMock).not.toHaveBeenCalled();
      expect(onClose).toHaveBeenCalledTimes(1);
    });
  });

  describe("Prowler Cloud subscribed", () => {
    beforeEach(() => {
      vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");
      updateScheduleMock.mockResolvedValue({ data: { id: "provider-1" } });
    });

    it("defaults to schedule mode and saves through the new schedule API", async () => {
      // Given
      const onClose = vi.fn();
      const onFooterChange = vi.fn();
      seedConnectedProvider();

      render(
        <LaunchStep
          onBack={vi.fn()}
          onClose={onClose}
          onFooterChange={onFooterChange}
          capability={SCAN_SCHEDULE_CAPABILITY.ADVANCED}
        />,
      );

      // Then advanced cadence selector is enabled
      expect(
        screen.getByRole("radio", { name: "On a schedule" }),
      ).toBeChecked();
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
        `/scans?tab=${SCAN_JOBS_TAB.SCHEDULED}`,
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
          capability={SCAN_SCHEDULE_CAPABILITY.ADVANCED}
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
      const toastPayload = toastMock.mock.calls[0]?.[0];
      expect(toastPayload.action.props.children.props.href).toBe(
        `/scans?tab=${SCAN_JOBS_TAB.ACTIVE}`,
      );
    });

    it("launches only an on-demand scan when run now is selected", async () => {
      // Given
      const user = userEvent.setup();
      const onClose = vi.fn();
      const onFooterChange = vi.fn();
      seedConnectedProvider();
      scanOnDemandMock.mockResolvedValue({ data: { id: "scan-1" } });

      render(
        <LaunchStep
          onBack={vi.fn()}
          onClose={onClose}
          onFooterChange={onFooterChange}
          capability={SCAN_SCHEDULE_CAPABILITY.ADVANCED}
        />,
      );
      await waitFor(() => expect(onFooterChange).toHaveBeenCalled());

      // When
      await user.click(
        screen.getByRole("radio", {
          name: "Run now",
        }),
      );
      await waitFor(() =>
        expect(lastFooterConfig(onFooterChange)?.actionLabel).toBe(
          "Launch scan",
        ),
      );
      await act(async () => {
        lastFooterConfig(onFooterChange)?.onAction?.();
      });

      // Then
      await waitFor(() => expect(scanOnDemandMock).toHaveBeenCalledTimes(1));
      expect(updateScheduleMock).not.toHaveBeenCalled();
      expect(scheduleDailyMock).not.toHaveBeenCalled();
      expect(onClose).toHaveBeenCalledTimes(1);
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
          capability={SCAN_SCHEDULE_CAPABILITY.ADVANCED}
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

    it("disables launch actions while schedule capability is loading", async () => {
      // Given
      const onFooterChange = vi.fn();
      seedConnectedProvider();

      render(
        <LaunchStep
          onBack={vi.fn()}
          onClose={vi.fn()}
          onFooterChange={onFooterChange}
          capability={SCAN_SCHEDULE_CAPABILITY.ADVANCED}
          isScheduleCapabilityLoading
        />,
      );

      // When
      await screen.findByText("Loading scan options...");
      await waitFor(() => expect(onFooterChange).toHaveBeenCalled());
      await act(async () => {
        lastFooterConfig(onFooterChange)?.onAction?.();
      });

      // Then
      expect(lastFooterConfig(onFooterChange)?.backDisabled).toBe(true);
      expect(lastFooterConfig(onFooterChange)?.actionDisabled).toBe(true);
      expect(scanOnDemandMock).not.toHaveBeenCalled();
      expect(updateScheduleMock).not.toHaveBeenCalled();
      expect(scheduleDailyMock).not.toHaveBeenCalled();
    });
  });

  describe("Prowler Cloud trial/onboarding (manual scan only)", () => {
    beforeEach(() => {
      vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");
      scanOnDemandMock.mockResolvedValue({ data: { id: "scan-1" } });
    });

    it("defaults to run now, locks schedule mode, and only launches a manual scan", async () => {
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
      expect(screen.getByRole("radio", { name: "Run now" })).toBeChecked();
      expect(
        screen.getByRole("radio", { name: "On a schedule" }),
      ).toBeDisabled();
      expect(
        screen.getByText(/scheduled scans are not available/i),
      ).toBeInTheDocument();
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

    it("uses the shared subscription error copy when a manual scan is blocked", async () => {
      // Given
      const onClose = vi.fn();
      const onFooterChange = vi.fn();
      const rawError =
        ACTION_ERROR_API_MESSAGES[ACTION_ERROR_STATUS.PAYMENT_REQUIRED];
      seedConnectedProvider();
      scanOnDemandMock.mockResolvedValue({
        error: rawError,
        status: ACTION_ERROR_STATUS.PAYMENT_REQUIRED,
      });

      render(
        <LaunchStep
          onBack={vi.fn()}
          onClose={onClose}
          onFooterChange={onFooterChange}
          capability={SCAN_SCHEDULE_CAPABILITY.MANUAL_ONLY}
        />,
      );
      await waitFor(() => expect(onFooterChange).toHaveBeenCalled());

      // When
      await act(async () => {
        lastFooterConfig(onFooterChange)?.onAction?.();
      });

      // Then
      await waitFor(() => expect(scanOnDemandMock).toHaveBeenCalledTimes(1));
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({
          variant: "destructive",
          title: "Unable to launch scan",
          description:
            ACTION_ERROR_MESSAGES[ACTION_ERROR_STATUS.PAYMENT_REQUIRED],
        }),
      );
      expect(toastMock.mock.calls[0]?.[0].description).not.toContain(rawError);
      expect(onClose).not.toHaveBeenCalled();
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
      expect(screen.getByText(/exceeded the usage limit/i)).toBeInTheDocument();
      await waitFor(() => expect(onFooterChange).toHaveBeenCalled());
      expect(lastFooterConfig(onFooterChange)?.actionDisabled).toBe(true);
    });
  });
});
