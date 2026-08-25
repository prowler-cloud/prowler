"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { useForm, useWatch } from "react-hook-form";

import {
  launchOrganizationScans,
  scheduleOrganizationDailyScans,
} from "@/actions/scans/scans";
import { updateSchedulesBulk } from "@/actions/schedules/schedules";
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
  describeSchedulesBulkFailures,
  getScanScheduleCapability,
  getScheduleFormDefaults,
  parseSchedulesBulkResult,
  scheduleFormSchema,
} from "@/lib/schedules";
import { isCloud } from "@/lib/shared/env";
import { useOrgSetupStore } from "@/store/organizations/store";
import {
  SCAN_JOBS_TAB,
  SCAN_SCHEDULE_CAPABILITY,
  type ScanScheduleCapability,
  type ScheduleFormValues,
} from "@/types";
import { TREE_ITEM_STATUS } from "@/types/tree";

import {
  getOrgCandidateNoun,
  getOrgProviderBadge,
  OrgCandidateNoun,
} from "./org-terminology";

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

function formatCandidateCount(count: number, noun: OrgCandidateNoun): string {
  return `${count} ${count === 1 ? noun.singular : noun.plural}`;
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
  const {
    organizationId,
    organizationExternalId,
    organizationType,
    createdProviderIds,
    reset,
  } = useOrgSetupStore();
  const noun = getOrgCandidateNoun(organizationType);
  const OrgBadge = getOrgProviderBadge(organizationType);

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

    const outcome = parseSchedulesBulkResult(result);
    const failedCount = outcome.failures.length;
    const failureReasons = describeSchedulesBulkFailures(outcome.failures);
    // A body we cannot read is not a failure: the endpoint commits each schedule
    // before answering, so blocking here would ask the user to save one twice.
    const updatedProviderIds = outcome.isIndeterminate
      ? createdProviderIds
      : outcome.updatedProviderIds;

    // Every provider failed: keep the wizard open to retry, and name the reason.
    if (updatedProviderIds.length === 0) {
      setIsLaunching(false);
      toast({
        variant: "destructive",
        title: "Unable to save scan schedules",
        description:
          failedCount > 0
            ? `The scan schedule could not be saved for ${formatCandidateCount(failedCount, noun)}${failureReasons ? `: ${failureReasons}.` : "."}`
            : `The scan schedule could not be saved for any ${noun.singular}.`,
      });
      return;
    }

    let initialScanFailureCount = 0;
    let initialScanSuccessCount = 0;
    let initialScanError: string | undefined;

    if (values.launchInitialScan) {
      const scanResult = organizationId
        ? await launchOrganizationScans(organizationId)
        : { error: "Organization ID is required" };

      if ("error" in scanResult) {
        initialScanFailureCount = updatedProviderIds.length;
        initialScanError = getActionErrorMessage(scanResult);
      } else {
        initialScanSuccessCount = scanResult.data.length;
      }
    }

    setIsLaunching(false);
    finishSuccess();

    const updatedCount = updatedProviderIds.length;
    const description =
      failedCount > 0
        ? `The schedule was saved for ${formatCandidateCount(updatedCount, noun)}, but ${formatCandidateCount(failedCount, noun)} could not be updated${failureReasons ? `: ${failureReasons}.` : "."}`
        : `The scan schedule was saved for ${formatCandidateCount(updatedCount, noun)}.`;
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
          ? initialScanError
            ? `${description} The initial organization scan could not be launched: ${initialScanError}`
            : `${description} Initial scans failed for ${formatCandidateCount(initialScanFailureCount, noun)}.`
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

    let successCount = 0;

    if (effectiveScheduleOption === SCAN_SCHEDULE.SINGLE) {
      const result = organizationId
        ? await launchOrganizationScans(organizationId)
        : { error: "Organization ID is required" };

      if ("error" in result) {
        setIsLaunching(false);
        toast({
          variant: "destructive",
          title: "Unable to launch organization scan",
          description: getActionErrorMessage(result),
        });
        return;
      }

      successCount = result.data.length;
    } else {
      const result = await scheduleOrganizationDailyScans(createdProviderIds);
      successCount = result.successCount;
    }
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
          ? `Daily scan scheduled for ${formatCandidateCount(successCount, noun)}.`
          : `Single scan launched for ${formatCandidateCount(successCount, noun)}.`,
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
          <OrgBadge size={32} />
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
            <h3 className="text-sm font-semibold">{noun.Plural} Connected!</h3>
          </div>

          <p className="text-text-neutral-secondary text-sm">
            Your {noun.plural} are connected to Prowler and ready to Scan!
          </p>

          {createdProviderIds.length === 0 && (
            <p className="text-text-error-primary text-sm">
              No successfully connected {noun.plural} are available to launch
              scans. Go back and retry connection tests.
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
                Scheduled scans are not available for trial accounts. These{" "}
                {noun.plural} will run a one-time manual scan now.
              </p>
            </div>
          ) : isDailyLegacy ? (
            <div className="flex flex-col gap-4">
              <p className="text-text-neutral-secondary text-sm">
                Select a Prowler scan schedule for these {noun.plural}.
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
