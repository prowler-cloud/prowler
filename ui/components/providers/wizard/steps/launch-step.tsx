"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { useForm } from "react-hook-form";

import { scanOnDemand } from "@/actions/scans";
import {
  SAVE_SCHEDULE_STATUS,
  saveScheduleWithInitialScan,
} from "@/components/scans/schedule/save-schedule";
import { ScanScheduleFields } from "@/components/scans/schedule/scan-schedule-fields";
import { Spinner } from "@/components/shadcn/spinner/spinner";
import { TreeStatusIcon } from "@/components/shadcn/tree-view/tree-status-icon";
import { CloudFeatureBadge } from "@/components/shared/cloud-feature-badge";
import { ToastAction, useToast } from "@/components/ui";
import { EntityInfo } from "@/components/ui/entities";
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
}

export function LaunchStep({
  onBack,
  onClose,
  onFooterChange,
  capability: capabilityProp,
  isScanLimitReached = false,
}: LaunchStepProps) {
  const { toast } = useToast();
  const { providerAlias, providerId, providerType, providerUid } =
    useProviderWizardStore();
  const [isLaunching, setIsLaunching] = useState(false);
  const form = useForm<ScheduleFormValues>({
    resolver: zodResolver(scheduleFormSchema),
    defaultValues: getScheduleFormDefaults(),
  });

  const capability = capabilityProp ?? getScanScheduleCapability(isCloud());
  const isManualOnly = capability === SCAN_SCHEDULE_CAPABILITY.MANUAL_ONLY;
  const isAdvanced = capability === SCAN_SCHEDULE_CAPABILITY.ADVANCED;
  const isActionBlocked =
    isLaunching || !providerId || (isManualOnly && isScanLimitReached);

  const launchOnDemandScan = async (): Promise<{ error?: unknown } | null> => {
    if (!providerId) return null;
    const formData = new FormData();
    formData.set("providerId", providerId);
    return scanOnDemand(formData);
  };

  const handleManualScan = async () => {
    setIsLaunching(true);
    const scanResult = await launchOnDemandScan();

    if (scanResult?.error) {
      setIsLaunching(false);
      toast({
        variant: "destructive",
        title: "Unable to launch scan",
        description: String(scanResult.error),
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
    if (!providerId) {
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

    const goToScans = (
      <ToastAction altText="Go to scans" asChild>
        <Link href={`/scans?tab=${SCAN_JOBS_TAB.ACTIVE}`}>Go to scans</Link>
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

    const launched = result.status === SAVE_SCHEDULE_STATUS.SAVED_AND_LAUNCHED;
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
    if (isManualOnly) {
      void handleManualScan();
      return;
    }
    void handleSaveSchedule();
  };

  useEffect(() => {
    const actionLabel = isManualOnly
      ? isLaunching
        ? "Launching scan..."
        : "Launch scan"
      : isLaunching
        ? "Saving..."
        : "Save";

    onFooterChange({
      showBack: true,
      backLabel: "Back",
      backDisabled: isLaunching,
      onBack,
      showAction: true,
      actionLabel,
      actionDisabled: isActionBlocked,
      actionType: WIZARD_FOOTER_ACTION_TYPE.BUTTON,
      onAction: () => actionRef.current(),
    });
  }, [isActionBlocked, isLaunching, isManualOnly, onBack, onFooterChange]);

  if (isLaunching) {
    return (
      <div className="flex min-h-[320px] items-center justify-center">
        <div className="flex items-center gap-3 py-2">
          <Spinner className="size-6" />
          <p className="text-sm font-medium">
            {isManualOnly ? "Launching scan..." : "Saving scan schedule..."}
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
        <h3 className="text-sm font-semibold">Account Connected!</h3>
      </div>

      <p className="text-text-neutral-secondary text-sm">
        Your account is connected to Prowler and ready to Scan!
      </p>

      {!providerId && (
        <p className="text-text-error-primary text-sm">
          Provider data is missing. Go back and test the connection again.
        </p>
      )}

      {isManualOnly ? (
        <div className="flex flex-col gap-3">
          <div className="flex items-center gap-2">
            <h3 className="text-text-neutral-primary text-sm font-medium">
              Scan Schedule
            </h3>
            <CloudFeatureBadge label="Available after onboarding" size="sm" />
          </div>
          <p className="text-text-neutral-secondary text-sm">
            Scheduled scans are not available yet. For now you can launch a
            manual scan to get immediate findings.
          </p>
          {isScanLimitReached && (
            <p className="text-text-error-primary text-sm">
              You have reached your scan limit, so additional scans are not
              available right now.
            </p>
          )}
        </div>
      ) : (
        <ScanScheduleFields
          form={form}
          disabled={isLaunching || !providerId}
          showLaunchInitialScan
          showNextScheduledCopy
          canUseAdvancedSchedule={isAdvanced}
          showCloudUpgradeBadge={!isAdvanced}
        />
      )}
    </div>
  );
}
