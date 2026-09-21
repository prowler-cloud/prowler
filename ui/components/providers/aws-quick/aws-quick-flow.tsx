"use client";

import { useSession } from "next-auth/react";

import { WizardFooterConfig } from "@/components/providers/wizard/steps/footer-controls";
import { getAWSQuickOnboardingTemplateLinks } from "@/lib/external-urls";
import { getScanScheduleCapability } from "@/lib/schedules";
import { isCloud } from "@/lib/shared/env";
import {
  SCAN_SCHEDULE_CAPABILITY,
  type ScanScheduleCapability,
} from "@/types/schedules";

import { AwsQuickConnectStep } from "./steps/aws-quick-connect-step";
import { AwsQuickNameStep } from "./steps/aws-quick-name-step";
import { AWS_QUICK_STEP, AwsQuickStep } from "./types";

interface AwsQuickFlowProps {
  step: AwsQuickStep;
  onStepChange: (step: AwsQuickStep) => void;
  onBack: () => void;
  onClose: () => void;
  onSelectOrganizations: () => void;
  onFooterChange: (config: WizardFooterConfig) => void;
  capability?: ScanScheduleCapability;
  isScanLimitReached?: boolean;
}

export function AwsQuickFlow({
  step,
  onStepChange,
  onBack,
  onClose,
  onSelectOrganizations,
  onFooterChange,
  capability: capabilityProp,
  isScanLimitReached = false,
}: AwsQuickFlowProps) {
  const { data: session } = useSession();
  const externalId = session?.tenantId ?? "";
  const capability = capabilityProp ?? getScanScheduleCapability(isCloud());
  const canLaunchScan =
    capability !== SCAN_SCHEDULE_CAPABILITY.BLOCKED && !isScanLimitReached;

  if (step === AWS_QUICK_STEP.CONNECT) {
    return (
      <AwsQuickConnectStep
        externalId={externalId}
        templateLinks={getAWSQuickOnboardingTemplateLinks(externalId)}
        onBack={onBack}
        onSelectOrganizations={onSelectOrganizations}
        onConnected={() => onStepChange(AWS_QUICK_STEP.NAME)}
        onFooterChange={onFooterChange}
      />
    );
  }

  return (
    <AwsQuickNameStep
      canLaunchScan={canLaunchScan}
      onClose={onClose}
      onFooterChange={onFooterChange}
    />
  );
}
