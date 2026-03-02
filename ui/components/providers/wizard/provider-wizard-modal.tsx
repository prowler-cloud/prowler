"use client";

import { ExternalLink, Info } from "lucide-react";

import { OrgAccountSelection } from "@/components/providers/organizations/org-account-selection";
import { OrgLaunchScan } from "@/components/providers/organizations/org-launch-scan";
import { OrgSetupForm } from "@/components/providers/organizations/org-setup-form";
import { Button } from "@/components/shadcn/button/button";
import { DialogHeader, DialogTitle } from "@/components/shadcn/dialog";
import { Modal } from "@/components/shadcn/modal";
import { useScrollHint } from "@/hooks/use-scroll-hint";
import { ORG_SETUP_PHASE, ORG_WIZARD_STEP } from "@/types/organizations";
import { PROVIDER_WIZARD_STEP } from "@/types/provider-wizard";

import { useProviderWizardController } from "./hooks/use-provider-wizard-controller";
import {
  getOrganizationsStepperOffset,
  getProviderWizardDocsDestination,
} from "./provider-wizard-modal.utils";
import { ConnectStep } from "./steps/connect-step";
import { CredentialsStep } from "./steps/credentials-step";
import { WIZARD_FOOTER_ACTION_TYPE } from "./steps/footer-controls";
import { LaunchStep } from "./steps/launch-step";
import { TestConnectionStep } from "./steps/test-connection-step";
import type { ProviderWizardInitialData } from "./types";
import { WizardStepper } from "./wizard-stepper";

interface ProviderWizardModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  initialData?: ProviderWizardInitialData;
}

export function ProviderWizardModal({
  open,
  onOpenChange,
  initialData,
}: ProviderWizardModalProps) {
  const {
    backToProviderFlow,
    currentStep,
    docsLink,
    handleClose,
    handleDialogOpenChange,
    handleTestSuccess,
    isProviderFlow,
    modalTitle,
    openOrganizationsFlow,
    orgCurrentStep,
    orgSetupPhase,
    resolvedFooterConfig,
    setCurrentStep,
    setFooterConfig,
    setOrgCurrentStep,
    setOrgSetupPhase,
    setProviderTypeHint,
    wizardVariant,
  } = useProviderWizardController({
    open,
    onOpenChange,
    initialData,
  });
  const scrollHintRefreshToken = `${wizardVariant}-${currentStep}-${orgCurrentStep}-${orgSetupPhase}`;
  const { containerRef, sentinelRef, showScrollHint } = useScrollHint({
    enabled: open,
    refreshToken: scrollHintRefreshToken,
  });
  const docsDestination = getProviderWizardDocsDestination(docsLink);

  return (
    <Modal
      open={open}
      onOpenChange={handleDialogOpenChange}
      size="4xl"
      className="flex !h-[90vh] !max-h-[90vh] !min-h-[90vh] !w-[calc(100vw-24px)] !max-w-[1192px] flex-col overflow-hidden p-4 sm:!w-[calc(100vw-40px)] sm:p-6 lg:!w-[calc(100vw-64px)] lg:p-8"
    >
      <DialogHeader className="gap-2 p-0">
        <DialogTitle className="text-lg font-semibold">
          {modalTitle}
        </DialogTitle>
        <div className="text-muted-foreground flex flex-wrap items-center gap-2 text-sm">
          <Info className="size-4 shrink-0" />
          <span>For assistance connecting a Cloud Provider visit</span>
          <Button variant="link" size="link-sm" className="h-auto p-0" asChild>
            <a href={docsLink} target="_blank" rel="noopener noreferrer">
              <ExternalLink className="size-3.5 shrink-0" />
              <span>{`Prowler Docs (${docsDestination})`}</span>
            </a>
          </Button>
        </div>
      </DialogHeader>

      <div className="mt-6 flex min-h-0 flex-1 flex-col overflow-hidden lg:mt-8 lg:flex-row">
        <div className="mb-4 box-border w-full shrink-0 lg:mb-0 lg:w-[328px]">
          {isProviderFlow ? (
            <WizardStepper currentStep={currentStep} />
          ) : (
            <WizardStepper
              currentStep={orgCurrentStep}
              stepOffset={getOrganizationsStepperOffset(
                orgCurrentStep,
                orgSetupPhase,
              )}
            />
          )}
        </div>
        <div aria-hidden className="hidden w-[100px] min-w-0 shrink lg:block" />

        <div className="relative flex-1 overflow-hidden">
          <div
            ref={containerRef}
            className="minimal-scrollbar h-full w-full overflow-y-scroll [scrollbar-gutter:stable] lg:ml-auto lg:max-w-[620px] xl:max-w-[700px]"
          >
            {isProviderFlow && currentStep === PROVIDER_WIZARD_STEP.CONNECT && (
              <ConnectStep
                onNext={() => setCurrentStep(PROVIDER_WIZARD_STEP.CREDENTIALS)}
                onSelectOrganizations={openOrganizationsFlow}
                onFooterChange={setFooterConfig}
                onProviderTypeChange={setProviderTypeHint}
              />
            )}

            {isProviderFlow &&
              currentStep === PROVIDER_WIZARD_STEP.CREDENTIALS && (
                <CredentialsStep
                  onNext={() => setCurrentStep(PROVIDER_WIZARD_STEP.TEST)}
                  onBack={() => setCurrentStep(PROVIDER_WIZARD_STEP.CONNECT)}
                  onFooterChange={setFooterConfig}
                />
              )}

            {isProviderFlow && currentStep === PROVIDER_WIZARD_STEP.TEST && (
              <TestConnectionStep
                onSuccess={handleTestSuccess}
                onResetCredentials={() =>
                  setCurrentStep(PROVIDER_WIZARD_STEP.CREDENTIALS)
                }
                onFooterChange={setFooterConfig}
              />
            )}

            {isProviderFlow && currentStep === PROVIDER_WIZARD_STEP.LAUNCH && (
              <LaunchStep
                onBack={() => setCurrentStep(PROVIDER_WIZARD_STEP.TEST)}
                onClose={handleClose}
                onFooterChange={setFooterConfig}
              />
            )}

            {!isProviderFlow && orgCurrentStep === ORG_WIZARD_STEP.SETUP && (
              <OrgSetupForm
                onBack={backToProviderFlow}
                onNext={() => {
                  setOrgCurrentStep(ORG_WIZARD_STEP.VALIDATE);
                }}
                onFooterChange={setFooterConfig}
                onPhaseChange={setOrgSetupPhase}
                initialPhase={orgSetupPhase}
              />
            )}

            {!isProviderFlow && orgCurrentStep === ORG_WIZARD_STEP.VALIDATE && (
              <OrgAccountSelection
                onBack={() => {
                  setOrgCurrentStep(ORG_WIZARD_STEP.SETUP);
                  setOrgSetupPhase(ORG_SETUP_PHASE.ACCESS);
                }}
                onNext={() => {
                  setOrgCurrentStep(ORG_WIZARD_STEP.LAUNCH);
                }}
                onSkip={() => {
                  setOrgCurrentStep(ORG_WIZARD_STEP.LAUNCH);
                }}
                onFooterChange={setFooterConfig}
              />
            )}

            {!isProviderFlow && orgCurrentStep === ORG_WIZARD_STEP.LAUNCH && (
              <OrgLaunchScan
                onClose={handleClose}
                onBack={() => {
                  setOrgCurrentStep(ORG_WIZARD_STEP.VALIDATE);
                }}
                onFooterChange={setFooterConfig}
              />
            )}

            {/* Sentinel element for IntersectionObserver scroll detection */}
            <div ref={sentinelRef} aria-hidden className="h-px shrink-0" />
          </div>

          {showScrollHint && (
            <div className="pointer-events-none absolute right-0 bottom-0 left-0 z-10">
              <div className="from-bg-neutral-secondary h-12 bg-gradient-to-t to-transparent" />
              <div className="absolute inset-x-0 bottom-2 flex justify-center">
                <span className="bg-bg-neutral-secondary/85 text-text-neutral-tertiary rounded-full px-3 py-1 text-xs backdrop-blur-sm">
                  Scroll to see more
                </span>
              </div>
            </div>
          )}
        </div>
      </div>

      {(resolvedFooterConfig.showBack ||
        resolvedFooterConfig.showSecondaryAction ||
        resolvedFooterConfig.showAction) && (
        <div className="mt-8 pt-6">
          <div className="flex items-center justify-between">
            <div>
              {resolvedFooterConfig.showBack && (
                <Button
                  type="button"
                  variant="outline"
                  size="xl"
                  disabled={resolvedFooterConfig.backDisabled}
                  onClick={resolvedFooterConfig.onBack}
                >
                  {resolvedFooterConfig.backLabel}
                </Button>
              )}
            </div>
            <div className="flex items-center gap-6">
              {resolvedFooterConfig.showSecondaryAction && (
                <Button
                  size={
                    resolvedFooterConfig.secondaryActionVariant === "link"
                      ? "link-sm"
                      : "xl"
                  }
                  className={
                    resolvedFooterConfig.secondaryActionVariant === "link"
                      ? "h-auto p-0"
                      : undefined
                  }
                  variant={resolvedFooterConfig.secondaryActionVariant}
                  type={
                    resolvedFooterConfig.secondaryActionType ===
                    WIZARD_FOOTER_ACTION_TYPE.SUBMIT
                      ? "submit"
                      : "button"
                  }
                  form={resolvedFooterConfig.secondaryActionFormId}
                  disabled={resolvedFooterConfig.secondaryActionDisabled}
                  onClick={
                    resolvedFooterConfig.secondaryActionType ===
                    WIZARD_FOOTER_ACTION_TYPE.BUTTON
                      ? resolvedFooterConfig.onSecondaryAction
                      : undefined
                  }
                >
                  {resolvedFooterConfig.secondaryActionLabel}
                </Button>
              )}

              {resolvedFooterConfig.showAction && (
                <Button
                  size="xl"
                  type={
                    resolvedFooterConfig.actionType ===
                    WIZARD_FOOTER_ACTION_TYPE.SUBMIT
                      ? "submit"
                      : "button"
                  }
                  form={resolvedFooterConfig.actionFormId}
                  disabled={resolvedFooterConfig.actionDisabled}
                  onClick={
                    resolvedFooterConfig.actionType ===
                    WIZARD_FOOTER_ACTION_TYPE.BUTTON
                      ? resolvedFooterConfig.onAction
                      : undefined
                  }
                >
                  {resolvedFooterConfig.actionLabel}
                </Button>
              )}
            </div>
          </div>
        </div>
      )}
    </Modal>
  );
}
