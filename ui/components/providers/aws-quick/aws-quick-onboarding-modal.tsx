"use client";

import { ExternalLink, Info, Loader2 } from "lucide-react";
import { useState } from "react";

import { getProviderWizardDocsDestination } from "@/components/providers/wizard/provider-wizard-modal.utils";
import {
  WIZARD_FOOTER_ACTION_TYPE,
  WizardFooterConfig,
} from "@/components/providers/wizard/steps/footer-controls";
import { WizardStepper } from "@/components/providers/wizard/wizard-stepper";
import { Button } from "@/components/shadcn/button/button";
import { DialogHeader, DialogTitle } from "@/components/shadcn/dialog";
import { Modal } from "@/components/shadcn/modal";
import { getProviderHelpText } from "@/lib/external-urls";
import { useProviderWizardStore } from "@/store/provider-wizard/store";
import { PROVIDER_WIZARD_STEP } from "@/types/provider-wizard";
import type { ScanScheduleCapability } from "@/types/schedules";

import { AwsQuickFlow } from "./aws-quick-flow";
import { AWS_QUICK_WIZARD_STEPS } from "./aws-quick-steps";
import { AWS_QUICK_STEP, AwsQuickStep } from "./types";

const EMPTY_FOOTER: WizardFooterConfig = {
  showBack: false,
  backLabel: "",
  showAction: false,
  actionLabel: "",
  actionType: WIZARD_FOOTER_ACTION_TYPE.BUTTON,
};

const DOCS_LINK = getProviderHelpText(
  "aws",
  PROVIDER_WIZARD_STEP.CREDENTIALS,
  "role",
).link;

interface AwsQuickOnboardingModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Return to the provider selection the user came from. */
  onBack: () => void;
  onSelectOrganizations: () => void;
  scanScheduleCapability?: ScanScheduleCapability;
  isScanLimitReached?: boolean;
}

/** Experimental AWS-only onboarding; lives next to the provider wizard, not inside it. */
export function AwsQuickOnboardingModal({
  open,
  onOpenChange,
  onBack,
  onSelectOrganizations,
  scanScheduleCapability,
  isScanLimitReached,
}: AwsQuickOnboardingModalProps) {
  const [step, setStep] = useState<AwsQuickStep>(AWS_QUICK_STEP.CONNECT);
  const [footer, setFooter] = useState<WizardFooterConfig>(EMPTY_FOOTER);

  const close = () => {
    setStep(AWS_QUICK_STEP.CONNECT);
    setFooter(EMPTY_FOOTER);
    useProviderWizardStore.getState().reset();
    onOpenChange(false);
  };

  return (
    <Modal
      open={open}
      onOpenChange={(next) => (next ? onOpenChange(true) : close())}
      size="4xl"
      className="flex !h-[90vh] !max-h-[90vh] !min-h-[90vh] !w-[calc(100vw-24px)] !max-w-[1192px] flex-col overflow-hidden p-4 sm:!w-[calc(100vw-40px)] sm:p-6 lg:!w-[calc(100vw-64px)] lg:p-8"
    >
      <DialogHeader className="gap-2 p-0">
        <DialogTitle className="text-lg font-semibold">
          Connect an AWS account
        </DialogTitle>
        <div className="text-muted-foreground flex flex-wrap items-center gap-2 text-sm">
          <Info className="size-4 shrink-0" />
          <span>For assistance connecting a Provider visit</span>
          <Button variant="link" size="link-sm" className="h-auto p-0" asChild>
            <a href={DOCS_LINK} target="_blank" rel="noopener noreferrer">
              <ExternalLink className="size-3.5 shrink-0" />
              <span>{`${getProviderWizardDocsDestination(DOCS_LINK)} Documentation`}</span>
            </a>
          </Button>
        </div>
      </DialogHeader>

      <div className="mt-6 flex min-h-0 flex-1 flex-col overflow-hidden lg:mt-8">
        <div className="flex min-h-0 flex-1 flex-col overflow-hidden lg:flex-row">
          <div className="mb-4 box-border w-full shrink-0 lg:mb-0 lg:w-[328px]">
            <WizardStepper currentStep={step} steps={AWS_QUICK_WIZARD_STEPS} />
          </div>
          <div
            aria-hidden
            className="hidden w-[100px] min-w-0 shrink lg:block"
          />
          <div className="flex min-h-0 flex-1 flex-col overflow-y-auto lg:max-w-[560px]">
            <AwsQuickFlow
              step={step}
              onStepChange={setStep}
              onBack={() => {
                close();
                onBack();
              }}
              onClose={close}
              onSelectOrganizations={() => {
                close();
                onSelectOrganizations();
              }}
              onFooterChange={setFooter}
              capability={scanScheduleCapability}
              isScanLimitReached={isScanLimitReached}
            />
          </div>
        </div>

        {(footer.showBack || footer.showAction) && (
          <div className="mt-8 flex items-center justify-between pt-6">
            <div>
              {footer.showBack && (
                <Button
                  type="button"
                  variant="outline"
                  size="xl"
                  disabled={footer.backDisabled}
                  onClick={footer.onBack}
                >
                  {footer.backLabel}
                </Button>
              )}
            </div>
            {footer.showAction && (
              <Button
                size="xl"
                type={
                  footer.actionType === WIZARD_FOOTER_ACTION_TYPE.SUBMIT
                    ? "submit"
                    : "button"
                }
                form={footer.actionFormId}
                disabled={footer.actionDisabled || footer.actionLoading}
                aria-busy={footer.actionLoading || undefined}
                onClick={
                  footer.actionType === WIZARD_FOOTER_ACTION_TYPE.BUTTON
                    ? footer.onAction
                    : undefined
                }
              >
                {footer.actionLoading && (
                  <Loader2 aria-hidden className="animate-spin" />
                )}
                {footer.actionLabel}
              </Button>
            )}
          </div>
        )}
      </div>
    </Modal>
  );
}
