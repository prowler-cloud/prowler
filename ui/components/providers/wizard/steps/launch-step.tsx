"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { useForm, useWatch } from "react-hook-form";

import { scanOnDemand } from "@/actions/scans";
import {
  SAVE_SCHEDULE_STATUS,
  saveScheduleWithInitialScan,
} from "@/components/scans/schedule/save-schedule";
import { ScanScheduleFields } from "@/components/scans/schedule/scan-schedule-fields";
import { Field, FieldLabel } from "@/components/shadcn";
import { ToastAction, useToast } from "@/components/shadcn";
import { EntityInfo } from "@/components/shadcn/entities";
import {
  RadioGroup,
  RadioGroupItem,
} from "@/components/shadcn/radio-group/radio-group";
import { Spinner } from "@/components/shadcn/spinner/spinner";
import { TreeStatusIcon } from "@/components/shadcn/tree-view/tree-status-icon";
import {
  CloudFeatureBadge,
  CloudFeatureBadgeLink,
} from "@/components/shared/cloud-feature-badge";
import { UsageLimitMessage } from "@/components/shared/usage-limit-message";
import {
  type ActionErrorResult,
  getActionErrorMessage,
  hasActionError,
} from "@/lib/action-errors";
import {
  getScanScheduleCapability,
  getScheduleFormDefaults,
  scheduleFormSchema,
} from "@/lib/schedules";
import { isCloud } from "@/lib/shared/env";
import { useProviderWizardStore } from "@/store/provider-wizard/store";
import { SCAN_JOBS_TAB } from "@/types";
import {
  SCAN_SCHEDULE_CAPABILITY,
  type ScanScheduleCapability,
  type ScheduleFormValues,
} from "@/types/schedules";
import { TREE_ITEM_STATUS } from "@/types/tree";

import {
  WIZARD_FOOTER_ACTION_TYPE,
  WizardFooterConfig,
} from "./footer-controls";

const LAUNCH_MODE = {
  NOW: "now",
  SCHEDULE: "schedule",
} as const;

type LaunchMode = (typeof LAUNCH_MODE)[keyof typeof LAUNCH_MODE];

interface LaunchStepProps {
  onBack: () => void;
  onClose: () => void;
  onFooterChange: (config: WizardFooterConfig) => void;
  /**
   * Schedule capability override. Absent in Prowler OSS (defaults to a
   * Cloud-vs-non-Cloud decision). The prowler-cloud overlay computes a
   * billing-aware capability and injects it here so trial/onboarding accounts
   * are limited to manual scans.
   */
  capability?: ScanScheduleCapability;
  /**
   * When true, the manual scan action is disabled (account scan quota reached).
   * Cloud-only signal; never set in OSS.
   */
  isScanLimitReached?: boolean;
  /**
   * Cloud-only loading state while billing is resolved into a schedule
   * capability. OSS leaves it false.
   */
  isScheduleCapabilityLoading?: boolean;
}

export function LaunchStep({
  onBack,
  onClose,
  onFooterChange,
  capability: capabilityProp,
  isScanLimitReached = false,
  isScheduleCapabilityLoading = false,
}: LaunchStepProps) {
  const { toast } = useToast();
  const { providerAlias, providerId, providerType, providerUid } =
    useProviderWizardStore();
  const capability = capabilityProp ?? getScanScheduleCapability(isCloud());
  const isManualOnly = capability === SCAN_SCHEDULE_CAPABILITY.MANUAL_ONLY;
  const isAdvanced = capability === SCAN_SCHEDULE_CAPABILITY.ADVANCED;
  const isDailyLegacy = capability === SCAN_SCHEDULE_CAPABILITY.DAILY_LEGACY;
  const isBlocked = capability === SCAN_SCHEDULE_CAPABILITY.BLOCKED;
  const canUseScheduleMode = isAdvanced || isDailyLegacy;
  const [isLaunching, setIsLaunching] = useState(false);
  const [mode, setMode] = useState<LaunchMode>(
    canUseScheduleMode ? LAUNCH_MODE.SCHEDULE : LAUNCH_MODE.NOW,
  );
  const form = useForm<ScheduleFormValues>({
    resolver: zodResolver(scheduleFormSchema),
    defaultValues: getScheduleFormDefaults(),
  });

  const isScheduleMode = canUseScheduleMode && mode === LAUNCH_MODE.SCHEDULE;
  const isLimitBlocked = mode === LAUNCH_MODE.NOW && isScanLimitReached;
  const isActionBlocked =
    isLaunching ||
    isScheduleCapabilityLoading ||
    !providerId ||
    isBlocked ||
    isLimitBlocked;
  const launchInitialScan = useWatch({
    control: form.control,
    name: "launchInitialScan",
  });

  const actionLabel = (() => {
    if (!isScheduleMode) {
      return isLaunching ? "Launching scan..." : "Launch scan";
    }

    if (isLaunching) {
      return launchInitialScan ? "Saving and launching..." : "Saving...";
    }

    return launchInitialScan ? "Save and launch scan" : "Save";
  })();

  useEffect(() => {
    if (!canUseScheduleMode && mode !== LAUNCH_MODE.NOW) {
      setMode(LAUNCH_MODE.NOW);
    }
  }, [canUseScheduleMode, mode]);

  const launchOnDemandScan = async (): Promise<ActionErrorResult | null> => {
    if (!providerId || isBlocked) return null;
    const formData = new FormData();
    formData.set("providerId", providerId);
    return scanOnDemand(formData);
  };

  const handleManualScan = async () => {
    if (isActionBlocked) {
      return;
    }

    setIsLaunching(true);
    const scanResult = await launchOnDemandScan();

    if (hasActionError(scanResult)) {
      setIsLaunching(false);
      toast({
        variant: "destructive",
        title: "Unable to launch scan",
        description: getActionErrorMessage(scanResult),
      });
      return;
    }

    setIsLaunching(false);
    onClose();
    toast({
      title: "Scan launched",
      description: "The scan was launched successfully.",
      action: (
        <ToastAction altText="Go to scans" asChild>
          <Link href={`/scans?tab=${SCAN_JOBS_TAB.ACTIVE}`}>Go to scans</Link>
        </ToastAction>
      ),
    });
  };

  const handleSaveSchedule = form.handleSubmit(async (values) => {
    if (!providerId || isBlocked || isScheduleCapabilityLoading) {
      return;
    }

    setIsLaunching(true);

    const result = await saveScheduleWithInitialScan({
      providerId,
      values,
      useLegacyDaily: !isAdvanced,
    });

    setIsLaunching(false);

    if (result.status === SAVE_SCHEDULE_STATUS.ERROR) {
      toast({
        variant: "destructive",
        title: "Unable to save scan schedule",
        description: result.message,
      });
      return;
    }

    onClose();

    const launched = result.status === SAVE_SCHEDULE_STATUS.SAVED_AND_LAUNCHED;
    const targetTab = launched ? SCAN_JOBS_TAB.ACTIVE : SCAN_JOBS_TAB.SCHEDULED;
    const goToScans = (
      <ToastAction altText="Go to scans" asChild>
        <Link href={`/scans?tab=${targetTab}`}>Go to scans</Link>
      </ToastAction>
    );

    if (result.status === SAVE_SCHEDULE_STATUS.SAVED_SCAN_FAILED) {
      toast({
        title: "Scan schedule saved",
        description: `The schedule was saved, but the initial scan could not be launched: ${result.message}`,
        action: goToScans,
      });
      return;
    }

    toast({
      title: launched
        ? "Scan schedule saved and initial scan launched"
        : "Scan schedule saved",
      description: launched
        ? "The schedule was saved and the initial scan was launched."
        : "The scan schedule was saved successfully.",
      action: goToScans,
    });
  });

  // Keep the latest action handler in a ref so the footer (synced via effect)
  // always invokes the current closure without re-running on every render.
  const actionRef = useRef<() => void>(() => {});
  actionRef.current = () => {
    if (isBlocked || isScheduleCapabilityLoading) {
      return;
    }

    if (!isScheduleMode) {
      void handleManualScan();
      return;
    }
    void handleSaveSchedule();
  };

  useEffect(() => {
    onFooterChange({
      showBack: true,
      backLabel: "Back",
      backDisabled: isLaunching || isScheduleCapabilityLoading,
      onBack,
      showAction: true,
      actionLabel,
      actionDisabled: isActionBlocked,
      actionType: WIZARD_FOOTER_ACTION_TYPE.BUTTON,
      onAction: () => actionRef.current(),
    });
  }, [
    isActionBlocked,
    isLaunching,
    isScheduleCapabilityLoading,
    actionLabel,
    isScheduleMode,
    launchInitialScan,
    mode,
    onBack,
    onFooterChange,
  ]);

  if (isLaunching || isScheduleCapabilityLoading) {
    return (
      <div className="flex min-h-[320px] items-center justify-center">
        <div className="flex items-center gap-3 py-2">
          <Spinner className="size-6" />
          <p className="text-sm font-medium">
            {isScheduleCapabilityLoading
              ? "Loading scan options..."
              : !isScheduleMode
                ? "Launching scan..."
                : "Saving scan schedule..."}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-6">
      {(providerId || providerUid) && (
        <EntityInfo
          cloudProvider={providerType ?? undefined}
          entityAlias={providerAlias ?? providerUid ?? providerId ?? undefined}
          entityId={providerUid ?? providerId ?? undefined}
        />
      )}

      <div className="flex items-center gap-3">
        <TreeStatusIcon status={TREE_ITEM_STATUS.SUCCESS} className="size-6" />
        <h3 className="text-sm font-semibold">Provider Connected!</h3>
      </div>

      <p className="text-text-neutral-secondary text-sm">
        Your provider is connected to Prowler and ready to Scan!
      </p>

      {!providerId && (
        <p className="text-text-error-primary text-sm">
          Provider data is missing. Go back and test the connection again.
        </p>
      )}

      <Field>
        <FieldLabel>Mode</FieldLabel>
        <RadioGroup
          value={mode}
          onValueChange={(value) => setMode(value as LaunchMode)}
          className="flex flex-row flex-wrap gap-6"
          aria-label="Scan mode"
        >
          <label className="flex items-center gap-2 text-sm">
            <RadioGroupItem
              value={LAUNCH_MODE.NOW}
              aria-label="Run now"
              disabled={isBlocked}
            />
            Run now
          </label>
          <label className="flex items-center gap-2 text-sm">
            <RadioGroupItem
              value={LAUNCH_MODE.SCHEDULE}
              aria-label="On a schedule"
              disabled={!canUseScheduleMode}
            />
            On a schedule
            {!canUseScheduleMode &&
              !isBlocked &&
              (isManualOnly ? (
                <CloudFeatureBadge label="Requires subscription" size="sm" />
              ) : (
                <CloudFeatureBadgeLink size="sm" />
              ))}
          </label>
        </RadioGroup>
      </Field>

      {isManualOnly && !isBlocked && (
        <p className="text-text-neutral-secondary text-sm">
          Scheduled scans are not available for this account. Run now to get
          immediate findings.
        </p>
      )}

      {(isLimitBlocked || isBlocked) && <UsageLimitMessage />}

      {isScheduleMode && (
        <ScanScheduleFields
          form={form}
          disabled={isLaunching || !providerId}
          showLaunchInitialScan
          showNextScheduledCopy
          canUseAdvancedSchedule={isAdvanced}
          showCloudUpgradeBadge={isDailyLegacy}
        />
      )}
    </div>
  );
}
