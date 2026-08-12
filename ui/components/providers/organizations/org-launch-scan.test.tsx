import { act, render, screen, waitFor } from "@testing-library/react";
import type { ComponentProps } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  ACTION_ERROR_API_MESSAGES,
  ACTION_ERROR_MESSAGES,
  ACTION_ERROR_STATUS,
} from "@/lib/action-errors";
import { useOrgSetupStore } from "@/store/organizations/store";
import {
  SCAN_JOBS_TAB,
  SCAN_SCHEDULE_CAPABILITY,
  SCHEDULE_FREQUENCY,
} from "@/types";

import { OrgLaunchScan } from "./org-launch-scan";

const {
  launchOrganizationScansMock,
  pushMock,
  scheduleOrganizationDailyScansMock,
  toastMock,
  updateSchedulesBulkMock,
} = vi.hoisted(() => ({
  launchOrganizationScansMock: vi.fn(),
  pushMock: vi.fn(),
  scheduleOrganizationDailyScansMock: vi.fn(),
  toastMock: vi.fn(),
  updateSchedulesBulkMock: vi.fn(),
}));

vi.mock("@/actions/scans/scans", () => ({
  launchOrganizationScans: launchOrganizationScansMock,
  scheduleOrganizationDailyScans: scheduleOrganizationDailyScansMock,
}));

vi.mock("@/actions/schedules/schedules", () => ({
  updateSchedulesBulk: updateSchedulesBulkMock,
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({
    push: pushMock,
  }),
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

const PROVIDER_IDS = ["provider-1", "provider-2"];

const lastFooterConfig = (onFooterChange: ReturnType<typeof vi.fn>) =>
  onFooterChange.mock.calls.at(-1)?.[0];

describe("OrgLaunchScan", () => {
  beforeEach(() => {
    vi.spyOn(Intl, "DateTimeFormat").mockReturnValue({
      resolvedOptions: () => ({ timeZone: "Europe/Madrid" }),
    } as Intl.DateTimeFormat);
    sessionStorage.clear();
    localStorage.clear();
    launchOrganizationScansMock.mockReset();
    pushMock.mockReset();
    scheduleOrganizationDailyScansMock.mockReset();
    toastMock.mockReset();
    updateSchedulesBulkMock.mockReset();
    launchOrganizationScansMock.mockResolvedValue({
      data: [
        { type: "scans", id: "scan-1" },
        { type: "scans", id: "scan-2" },
      ],
    });
    scheduleOrganizationDailyScansMock.mockResolvedValue({
      successCount: 2,
      failureCount: 0,
      totalCount: 2,
      errors: [],
    });
    updateSchedulesBulkMock.mockResolvedValue({
      data: {
        updated: PROVIDER_IDS,
        failed: [],
      },
    });
    useOrgSetupStore.getState().reset();
    useOrgSetupStore
      .getState()
      .setOrganization("org-1", "My Organization", "o-abc123def4");
    useOrgSetupStore.getState().setCreatedProviderIds(PROVIDER_IDS);
  });

  describe("when capability is ADVANCED", () => {
    it("should save schedules through the bulk endpoint", async () => {
      // Given
      const onFooterChange = vi.fn();

      render(
        <OrgLaunchScan
          onClose={vi.fn()}
          onBack={vi.fn()}
          onFooterChange={onFooterChange}
          capability={SCAN_SCHEDULE_CAPABILITY.ADVANCED}
        />,
      );

      // When
      await screen.findByText("Scan Schedule");
      await act(async () => {
        lastFooterConfig(onFooterChange)?.onAction?.();
      });

      // Then
      await waitFor(() =>
        expect(updateSchedulesBulkMock).toHaveBeenCalledTimes(1),
      );
      expect(updateSchedulesBulkMock).toHaveBeenCalledWith(
        PROVIDER_IDS,
        expect.objectContaining({
          scan_enabled: true,
          scan_frequency: SCHEDULE_FREQUENCY.DAILY,
          scan_hour: expect.any(Number),
          scan_timezone: "Europe/Madrid",
        }),
      );
      expect(launchOrganizationScansMock).not.toHaveBeenCalled();
      expect(pushMock).toHaveBeenCalledWith("/providers");
      expect(
        toastMock.mock.calls[0]?.[0].action.props.children.props.href,
      ).toBe(`/scans?tab=${SCAN_JOBS_TAB.SCHEDULED}`);
    });

    it("should disable launch actions while schedule capability is loading", async () => {
      // Given
      const onFooterChange = vi.fn();

      render(
        <OrgLaunchScan
          onClose={vi.fn()}
          onBack={vi.fn()}
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
      expect(updateSchedulesBulkMock).not.toHaveBeenCalled();
      expect(launchOrganizationScansMock).not.toHaveBeenCalled();
    });

    it("should surface an error toast and stay on the wizard when the bulk update fails", async () => {
      // Given
      const onClose = vi.fn();
      const onFooterChange = vi.fn();
      updateSchedulesBulkMock.mockResolvedValue({
        error: ACTION_ERROR_API_MESSAGES[ACTION_ERROR_STATUS.PAYMENT_REQUIRED],
        status: ACTION_ERROR_STATUS.PAYMENT_REQUIRED,
      });

      render(
        <OrgLaunchScan
          onClose={onClose}
          onBack={vi.fn()}
          onFooterChange={onFooterChange}
          capability={SCAN_SCHEDULE_CAPABILITY.ADVANCED}
        />,
      );

      // When
      await screen.findByText("Scan Schedule");
      await act(async () => {
        lastFooterConfig(onFooterChange)?.onAction?.();
      });

      // Then
      await waitFor(() =>
        expect(toastMock).toHaveBeenCalledWith(
          expect.objectContaining({
            variant: "destructive",
            title: "Unable to save scan schedules",
            description:
              ACTION_ERROR_MESSAGES[ACTION_ERROR_STATUS.PAYMENT_REQUIRED],
          }),
        ),
      );
      expect(launchOrganizationScansMock).not.toHaveBeenCalled();
      expect(pushMock).not.toHaveBeenCalled();
      expect(onClose).not.toHaveBeenCalled();
    });
  });

  describe("when capability is DAILY_LEGACY", () => {
    it("should keep the legacy daily scheduling path", async () => {
      // Given
      const onFooterChange = vi.fn();

      render(
        <OrgLaunchScan
          onClose={vi.fn()}
          onBack={vi.fn()}
          onFooterChange={onFooterChange}
          capability={SCAN_SCHEDULE_CAPABILITY.DAILY_LEGACY}
        />,
      );

      // When
      await screen.findByText(
        "Select a Prowler scan schedule for these accounts.",
      );
      await act(async () => {
        lastFooterConfig(onFooterChange)?.onAction?.();
      });

      // Then
      await waitFor(() =>
        expect(scheduleOrganizationDailyScansMock).toHaveBeenCalledWith(
          PROVIDER_IDS,
        ),
      );
      expect(updateSchedulesBulkMock).not.toHaveBeenCalled();
      expect(launchOrganizationScansMock).not.toHaveBeenCalled();
      expect(
        toastMock.mock.calls[0]?.[0].action.props.children.props.href,
      ).toBe(`/scans?tab=${SCAN_JOBS_TAB.SCHEDULED}`);
    });
  });

  describe("when capability is MANUAL_ONLY", () => {
    it("should launch single scans without rendering schedule controls", async () => {
      // Given
      const onFooterChange = vi.fn();

      render(
        <OrgLaunchScan
          onClose={vi.fn()}
          onBack={vi.fn()}
          onFooterChange={onFooterChange}
          capability={SCAN_SCHEDULE_CAPABILITY.MANUAL_ONLY}
        />,
      );

      // When
      expect(
        screen.getByText(
          /scheduled scans are not available for trial accounts/i,
        ),
      ).toBeInTheDocument();
      expect(screen.queryByRole("combobox")).not.toBeInTheDocument();
      await act(async () => {
        lastFooterConfig(onFooterChange)?.onAction?.();
      });

      // Then
      await waitFor(() =>
        expect(launchOrganizationScansMock).toHaveBeenCalledWith("org-1"),
      );
      expect(updateSchedulesBulkMock).not.toHaveBeenCalled();
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({
          description: "Single scan launched for 2 accounts.",
        }),
      );
      expect(
        toastMock.mock.calls[0]?.[0].action.props.children.props.href,
      ).toBe(`/scans?tab=${SCAN_JOBS_TAB.ACTIVE}`);
    });
  });

  describe("when capability is BLOCKED", () => {
    it("should disable the action without calling scans or schedules", async () => {
      // Given
      const onFooterChange = vi.fn();

      render(
        <OrgLaunchScan
          onClose={vi.fn()}
          onBack={vi.fn()}
          onFooterChange={onFooterChange}
          capability={SCAN_SCHEDULE_CAPABILITY.BLOCKED}
        />,
      );

      // When
      await waitFor(() => {
        expect(lastFooterConfig(onFooterChange)?.actionDisabled).toBe(true);
      });
      await act(async () => {
        lastFooterConfig(onFooterChange)?.onAction?.();
      });

      // Then
      expect(screen.getByText(/exceeded the usage limit/i)).toBeInTheDocument();
      expect(updateSchedulesBulkMock).not.toHaveBeenCalled();
      expect(launchOrganizationScansMock).not.toHaveBeenCalled();
    });
  });
});
