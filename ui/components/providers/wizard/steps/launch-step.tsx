"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { useForm } from "react-hook-form";

import { scanOnDemand } from "@/actions/scans";
import { updateSchedule } from "@/actions/schedules";
import { ScanScheduleFields } from "@/components/scans/schedule/scan-schedule-fields";
import { Spinner } from "@/components/shadcn/spinner/spinner";
import { TreeStatusIcon } from "@/components/shadcn/tree-view/tree-status-icon";
import { ToastAction, useToast } from "@/components/ui";
import {
  buildScheduleUpdatePayload,
  getScheduleFormDefaults,
  scheduleFormSchema,
} from "@/lib/schedules";
import { useProviderWizardStore } from "@/store/provider-wizard/store";
import { SCAN_JOBS_TAB } from "@/types";
import type { ScheduleFormValues } from "@/types/schedules";
import { TREE_ITEM_STATUS } from "@/types/tree";

import {
  WIZARD_FOOTER_ACTION_TYPE,
  WizardFooterConfig,
} from "./footer-controls";

interface LaunchStepProps {
  onBack: () => void;
  onClose: () => void;
  onFooterChange: (config: WizardFooterConfig) => void;
}

export function LaunchStep({
  onBack,
  onClose,
  onFooterChange,
}: LaunchStepProps) {
  const { toast } = useToast();
  const { providerId } = useProviderWizardStore();
  const [isLaunching, setIsLaunching] = useState(false);
  const form = useForm<ScheduleFormValues>({
    resolver: zodResolver(scheduleFormSchema),
    defaultValues: getScheduleFormDefaults(),
  });
  const launchActionRef = useRef<() => void>(() => {});

  const handleLaunchScan = form.handleSubmit(async (values) => {
    if (!providerId) {
      return;
    }

    setIsLaunching(true);
    const scheduleResult = await updateSchedule(
      providerId,
      buildScheduleUpdatePayload(values),
    );

    if (scheduleResult?.error) {
      setIsLaunching(false);
      toast({
        variant: "destructive",
        title: "Unable to save scan schedule",
        description: String(scheduleResult.error),
      });
      return;
    }

    if (values.launchInitialScan) {
      const formData = new FormData();
      formData.set("providerId", providerId);
      const scanResult = await scanOnDemand(formData);

      if (scanResult?.error) {
        setIsLaunching(false);
        toast({
          variant: "destructive",
          title: "Scan schedule saved",
          description: `Initial scan failed: ${String(scanResult.error)}`,
        });
        return;
      }
    }

    setIsLaunching(false);
    onClose();
    toast({
      title: values.launchInitialScan
        ? "Scan schedule saved and initial scan launched"
        : "Scan schedule saved",
      description: values.launchInitialScan
        ? "The schedule was saved and the initial scan was launched."
        : "The scan schedule was saved successfully.",
      action: (
        <ToastAction altText="Go to scans" asChild>
          <Link href={`/scans?tab=${SCAN_JOBS_TAB.ACTIVE}`}>Go to scans</Link>
        </ToastAction>
      ),
    });
  });

  launchActionRef.current = () => {
    void handleLaunchScan();
  };

  useEffect(() => {
    onFooterChange({
      showBack: true,
      backLabel: "Back",
      backDisabled: isLaunching,
      onBack,
      showAction: true,
      actionLabel: isLaunching ? "Launching scans..." : "Launch scan",
      actionDisabled: isLaunching || !providerId,
      actionType: WIZARD_FOOTER_ACTION_TYPE.BUTTON,
      onAction: () => {
        launchActionRef.current();
      },
    });
  }, [isLaunching, onBack, onFooterChange, providerId]);

  if (isLaunching) {
    return (
      <div className="flex min-h-[320px] items-center justify-center">
        <div className="flex items-center gap-3 py-2">
          <Spinner className="size-6" />
          <p className="text-sm font-medium">Launching scans...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-6">
      <div className="flex items-center gap-3">
        <TreeStatusIcon status={TREE_ITEM_STATUS.SUCCESS} className="size-6" />
        <h3 className="text-sm font-semibold">Connection validated!</h3>
      </div>

      <p className="text-text-neutral-secondary text-sm">
        Choose when Prowler should scan this provider.
      </p>

      {!providerId && (
        <p className="text-text-error-primary text-sm">
          Provider data is missing. Go back and test the connection again.
        </p>
      )}

      <ScanScheduleFields
        form={form}
        disabled={isLaunching || !providerId}
        showLaunchInitialScan
      />
    </div>
  );
}
