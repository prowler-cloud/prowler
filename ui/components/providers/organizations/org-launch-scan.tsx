"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { useForm, useWatch } from "react-hook-form";

import { launchOrganizationScans } from "@/actions/scans/scans";
import { updateSchedulesBulk } from "@/actions/schedules/schedules";
import { AWSProviderBadge } from "@/components/icons/providers-badge";
import {
  WIZARD_FOOTER_ACTION_TYPE,
  WizardFooterConfig,
} from "@/components/providers/wizard/steps/footer-controls";
import { ScanScheduleFields } from "@/components/scans/schedule/scan-schedule-fields";
import { ToastAction, useToast } from "@/components/shadcn";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";
import { Spinner } from "@/components/shadcn/spinner/spinner";
import { TreeStatusIcon } from "@/components/shadcn/tree-view/tree-status-icon";
import { UsageLimitMessage } from "@/components/shared/usage-limit-message";
import { getActionErrorMessage, hasActionError } from "@/lib/action-errors";
import {
  buildScheduleUpdatePayload,
  getScanScheduleCapability,
  getScheduleFormDefaults,
  scheduleFormSchema,
} from "@/lib/schedules";
import { isCloud } from "@/lib/shared/env";
import { useOrgSetupStore } from "@/store/organizations/store";
import {
  SCAN_JOBS_TAB,
  SCAN_SCHEDULE_CAPABILITY,
  type ScanScheduleCapability,
  type ScheduleFormValues,
  type SchedulesBulkResponse,
} from "@/types";
import { TREE_ITEM_STATUS } from "@/types/tree";

interface OrgLaunchScanProps {
  onClose: () => void;
  onBack: () => void;
  onFooterChange: (config: WizardFooterConfig) => void;
  /**
   * Schedule capability override. Prowler Cloud passes MANUAL_ONLY/BLOCKED for
   * billing-limited tenants; OSS falls back to an environment-based capability.
   */
  capability?: ScanScheduleCapability;
  /** Cloud-only manual scan quota signal. */
  isScanLimitReached?: boolean;
  /**
   * Cloud-only loading state while billing is resolved into a schedule
   * capability. OSS leaves it false.
   */
  isScheduleCapabilityLoading?: boolean;
}

const SCAN_SCHEDULE = {
  DAILY: "daily",
  SINGLE: "single",
} as const;

type ScanScheduleOption = (typeof SCAN_SCHEDULE)[keyof typeof SCAN_SCHEDULE];

function getStringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
}

/**
 * Providers whose schedule was actually saved. The backend reports successes
 * under `updated`, populated only after each provider's schedule commits, so
 * it already excludes failures — no client-side subtraction is needed.
 */
function getUpdatedProviderIds(result: SchedulesBulkResponse): string[] {
  return getStringArray(result.data?.attributes?.updated);
}

function getFailedCount(result: SchedulesBulkResponse): number {
  const failed = result.data?.attributes?.failed;
  return Array.isArray(failed) ? failed.length : 0;
}

function formatAccountCount(count: number): string {
  return `${count} account${count === 1 ? "" : "s"}`;
}

function getScansHref(tab: (typeof SCAN_JOBS_TAB)[keyof typeof SCAN_JOBS_TAB]) {
  return `/scans?tab=${tab}`;
}

export function OrgLaunchScan({
  onClose,
  onBack,
  onFooterChange,
  capability,
  isScanLimitReached = false,
  isScheduleCapabilityLoading = false,
}: OrgLaunchScanProps) {
  const router = useRouter();
  const { toast } = useToast();
  const { organizationExternalId, createdProviderIds, reset } =
    useOrgSetupStore();

  const resolvedCapability = capability ?? getScanScheduleCapability(isCloud());
  const isAdvanced = resolvedCapability === SCAN_SCHEDULE_CAPABILITY.ADVANCED;
  const isDailyLegacy =
    resolvedCapability === SCAN_SCHEDULE_CAPABILITY.DAILY_LEGACY;
  const isManualOnly =
    resolvedCapability === SCAN_SCHEDULE_CAPABILITY.MANUAL_ONLY;
  const isBlocked =
    resolvedCapability === SCAN_SCHEDULE_CAPABILITY.BLOCKED ||
    (isManualOnly && isScanLimitReached);

  const [isLaunching, setIsLaunching] = useState(false);
  const [scheduleOption, setScheduleOption] = useState<ScanScheduleOption>(
    SCAN_SCHEDULE.DAILY,
  );
  const form = useForm<ScheduleFormValues>({
    resolver: zodResolver(scheduleFormSchema),
    defaultValues: getScheduleFormDefaults(),
  });
  const launchInitialScan = useWatch({
    control: form.control,
    name: "launchInitialScan",
  });
  const launchActionRef = useRef<() => void>(() => {});

  const effectiveScheduleOption = isManualOnly
    ? SCAN_SCHEDULE.SINGLE
    : scheduleOption;
  const actionDisabled =
    isLaunching ||
    isScheduleCapabilityLoading ||
    isBlocked ||
    createdProviderIds.length === 0;
  const actionLabel = isAdvanced
    ? isLaunching
      ? launchInitialScan
        ? "Saving and launching..."
        : "Saving..."
      : launchInitialScan
        ? "Save and launch scan"
        : "Save"
    : isLaunching
      ? "Launching scans..."
      : "Launch scan";

  const finishSuccess = () => {
    reset();
    onClose();
    router.push("/providers");
  };

  const handleAdvancedSchedule = form.handleSubmit(async (values) => {
    if (actionDisabled || !isAdvanced) {
      return;
    }

    setIsLaunching(true);

    const result = await updateSchedulesBulk(
      createdProviderIds,
      buildScheduleUpdatePayload(values),
    );

    if (hasActionError(result)) {
      setIsLaunching(false);
      toast({
        variant: "destructive",
        title: "Unable to save scan schedules",
        description: getActionErrorMessage(result),
      });
      return;
    }

    const updatedProviderIds = getUpdatedProviderIds(result);
    const failedCount = getFailedCount(result);

    // No provider was actually updated (e.g. the endpoint returned 200 but every
    // schedule failed). Surface it as an error and keep the wizard open to retry
    // instead of navigating away with a misleading "saved for 0 accounts" toast.
    if (updatedProviderIds.length === 0) {
      setIsLaunching(false);
      toast({
        variant: "destructive",
        title: "Unable to save scan schedules",
        description:
          failedCount > 0
            ? `The scan schedule could not be saved for ${formatAccountCount(failedCount)}.`
            : "The scan schedule could not be saved for any account.",
      });
      return;
    }

    let initialScanFailureCount = 0;
    let initialScanSuccessCount = 0;

    if (values.launchInitialScan) {
      const scanResult = await launchOrganizationScans(
        updatedProviderIds,
        SCAN_SCHEDULE.SINGLE,
      );
      initialScanFailureCount = scanResult.failureCount;
      initialScanSuccessCount = scanResult.successCount;
    }

    setIsLaunching(false);
    finishSuccess();

    const updatedCount = updatedProviderIds.length;
    const description =
      failedCount > 0
        ? `The schedule was saved for ${formatAccountCount(updatedCount)}, but ${formatAccountCount(failedCount)} could not be updated.`
        : `The scan schedule was saved for ${formatAccountCount(updatedCount)}.`;
    const targetTab =
      initialScanSuccessCount > 0
        ? SCAN_JOBS_TAB.ACTIVE
        : SCAN_JOBS_TAB.SCHEDULED;

    toast({
      title:
        values.launchInitialScan && initialScanFailureCount === 0
          ? "Scan schedules saved and initial scans launched"
          : "Scan schedules saved",
      description:
        initialScanFailureCount > 0
          ? `${description} Initial scans failed for ${formatAccountCount(initialScanFailureCount)}.`
          : description,
      action: (
        <ToastAction altText="Go to scans" asChild>
          <Link href={getScansHref(targetTab)}>Go to scans</Link>
        </ToastAction>
      ),
    });
  });

  const handleLegacyLaunch = async () => {
    if (actionDisabled || isAdvanced) {
      return;
    }

    setIsLaunching(true);

    const result = await launchOrganizationScans(
      createdProviderIds,
      effectiveScheduleOption,
    );
    const successCount = result.successCount;
    const targetTab =
      effectiveScheduleOption === SCAN_SCHEDULE.SINGLE
        ? SCAN_JOBS_TAB.ACTIVE
        : SCAN_JOBS_TAB.SCHEDULED;

    setIsLaunching(false);
    finishSuccess();

    toast({
      title: "Scan Launched",
      description:
        effectiveScheduleOption === SCAN_SCHEDULE.DAILY
          ? `Daily scan scheduled for ${formatAccountCount(successCount)}.`
          : `Single scan launched for ${formatAccountCount(successCount)}.`,
      action: (
        <ToastAction altText="Go to scans" asChild>
          <Link href={getScansHref(targetTab)}>Go to scans</Link>
        </ToastAction>
      ),
    });
  };

  launchActionRef.current = () => {
    if (isAdvanced) {
      void handleAdvancedSchedule();
      return;
    }
    void handleLegacyLaunch();
  };

  useEffect(() => {
    onFooterChange({
      showBack: true,
      backLabel: "Back",
      backDisabled: isLaunching || isScheduleCapabilityLoading,
      onBack,
      showAction: true,
      actionLabel,
      actionDisabled,
      actionType: WIZARD_FOOTER_ACTION_TYPE.BUTTON,
      onAction: () => {
        launchActionRef.current();
      },
    });
  }, [
    actionDisabled,
    actionLabel,
    createdProviderIds.length,
    isAdvanced,
    isLaunching,
    isScheduleCapabilityLoading,
    launchInitialScan,
    onBack,
    onFooterChange,
  ]);

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-8">
      <div className="flex flex-col gap-3">
        <div className="flex items-center gap-4">
          <AWSProviderBadge size={32} />
          <h3 className="text-base font-semibold">My Organization</h3>
        </div>

        <div className="ml-12 flex items-center gap-3">
          <span className="text-text-neutral-tertiary text-xs">UID:</span>
          <div className="bg-bg-neutral-tertiary border-border-input-primary inline-flex h-10 items-center rounded-full border px-4">
            <span className="text-xs font-medium">
              {organizationExternalId || "N/A"}
            </span>
          </div>
        </div>
      </div>

      {isLaunching || isScheduleCapabilityLoading ? (
        <div className="flex min-h-[220px] items-center justify-center">
          <div className="flex items-center gap-3 py-2">
            <Spinner className="size-6" />
            <p className="text-sm font-medium">
              {isScheduleCapabilityLoading
                ? "Loading scan options..."
                : isAdvanced
                  ? "Saving scan schedules..."
                  : "Launching scans..."}
            </p>
          </div>
        </div>
      ) : (
        <div className="flex max-w-2xl flex-col gap-6">
          <div className="flex items-center gap-3">
            <TreeStatusIcon
              status={TREE_ITEM_STATUS.SUCCESS}
              className="size-6"
            />
            <h3 className="text-sm font-semibold">Accounts Connected!</h3>
          </div>

          <p className="text-text-neutral-secondary text-sm">
            Your accounts are connected to Prowler and ready to Scan!
          </p>

          {createdProviderIds.length === 0 && (
            <p className="text-text-error-primary text-sm">
              No successfully connected accounts are available to launch scans.
              Go back and retry connection tests.
            </p>
          )}

          {isBlocked ? (
            <UsageLimitMessage />
          ) : isAdvanced ? (
            <ScanScheduleFields
              form={form}
              disabled={isLaunching}
              showLaunchInitialScan
              showNextScheduledCopy
            />
          ) : isManualOnly ? (
            <div className="flex flex-col gap-3">
              <p className="text-text-neutral-secondary text-sm">
                Scheduled scans are not available for trial accounts. These
                accounts will run a one-time manual scan now.
              </p>
            </div>
          ) : isDailyLegacy ? (
            <div className="flex flex-col gap-4">
              <p className="text-text-neutral-secondary text-sm">
                Select a Prowler scan schedule for these accounts.
              </p>
              <Select
                value={scheduleOption}
                onValueChange={(value) =>
                  setScheduleOption(value as ScanScheduleOption)
                }
                disabled={isLaunching}
              >
                <SelectTrigger className="w-full max-w-[376px]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={SCAN_SCHEDULE.DAILY}>
                    Scan Daily (every 24 hours)
                  </SelectItem>
                  <SelectItem value={SCAN_SCHEDULE.SINGLE}>
                    Run a single scan (no recurring schedule)
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
          ) : null}
        </div>
      )}
    </div>
  );
}
