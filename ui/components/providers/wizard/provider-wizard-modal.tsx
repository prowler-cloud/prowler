"use client";

import { Loader2 } from "lucide-react";

import { AzureOrgSetupForm } from "@/components/providers/organizations/azure-org-setup-form";
import { GcpOrgSetupForm } from "@/components/providers/organizations/gcp-org-setup-form";
import { OrgAccountSelection } from "@/components/providers/organizations/org-account-selection";
import { OrgLaunchScan } from "@/components/providers/organizations/org-launch-scan";
import { OrgSetupForm } from "@/components/providers/organizations/org-setup-form";
import { Button } from "@/components/shadcn/button/button";
import { DialogHeader, DialogTitle } from "@/components/shadcn/dialog";
import { SidePanelHostModal } from "@/components/side-panel/side-panel-host-modal";
import { useScanScheduleCapability } from "@/hooks/use-scan-schedule-capability";
import { useScrollHint } from "@/hooks/use-scroll-hint";
import {
  dispatchProviderFunnel,
  PROVIDER_FUNNEL_STEP,
} from "@/lib/provider-funnel/provider-funnel-events";
import {
  ORG_SETUP_PHASE,
  ORG_WIZARD_STEP,
  ORGANIZATION_TYPE,
} from "@/types/organizations";
import { PROVIDER_WIZARD_STEP } from "@/types/provider-wizard";
import type { ScanScheduleCapability } from "@/types/schedules";

import { useProviderWizardController } from "./hooks/use-provider-wizard-controller";
import { LighthouseConnectHelp } from "./lighthouse-connect-help";
import {
  getProviderWizardDocsDestination,
  getProviderWizardSteps,
} from "./provider-wizard-modal.utils";
import { ConnectStep } from "./steps/connect-step";
import { WIZARD_FOOTER_ACTION_TYPE } from "./steps/footer-controls";
import { LaunchStep } from "./steps/launch-step";
import type { OrgWizardInitialData, ProviderWizardInitialData } from "./types";
import {
  getActiveStepIndex,
  ORGANIZATION_WIZARD_STEPS,
  WizardStepper,
} from "./wizard-stepper";

interface ProviderWizardModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  initialData?: ProviderWizardInitialData;
  orgInitialData?: OrgWizardInitialData;
  refreshOnClose?: boolean;
  /** Cloud overlay seam; defaults to the environment-resolved capability. */
  scanScheduleCapability?: ScanScheduleCapability;
  /** Cloud-only manual scan quota signal. */
  isScanLimitReached?: boolean;
}

export function ProviderWizardModal({
  open,
  onOpenChange,
  initialData,
  orgInitialData,
  refreshOnClose,
  scanScheduleCapability,
  isScanLimitReached,
}: ProviderWizardModalProps) {
  const {
    backToProviderFlow,
    connectionMethod,
    currentStep,
    docsLink,
    handleClose,
    handleDialogOpenChange,
    handleTestSuccess,
    isDirectCredentialsEntry,
    isOrgDirectEntry,
    isProviderFlow,
    mode,
    modalTitle,
    openOrganizationsFlow,
    organizationType,
    orgCurrentStep,
    orgSetupPhase,
    providerTypeHint,
    resolvedFooterConfig,
    setCurrentStep,
    setFooterConfig,
    setOrgCurrentStep,
    setOrgSetupPhase,
    setProviderTypeHint,
    stepName,
    wizardVariant,
  } = useProviderWizardController({
    open,
    onOpenChange,
    initialData,
    orgInitialData,
    refreshOnClose,
  });
  const scrollHintRefreshToken = `${wizardVariant}-${currentStep}-${orgCurrentStep}-${orgSetupPhase}`;
  const { containerRef, sentinelRef, showScrollHint } = useScrollHint({
    enabled: open,
    refreshToken: scrollHintRefreshToken,
  });
  const {
    capability: resolvedScanScheduleCapability,
    isScheduleCapabilityLoading,
  } = useScanScheduleCapability(scanScheduleCapability);
  const docsDestination = getProviderWizardDocsDestination(docsLink);
  const stepperSteps = isProviderFlow
    ? getProviderWizardSteps(mode)
    : ORGANIZATION_WIZARD_STEPS;
  const stepperCurrent = isProviderFlow ? currentStep : orgCurrentStep;
  const stepLabel =
    stepperSteps[getActiveStepIndex(stepperCurrent, stepperSteps.length)].label;

  return (
    <SidePanelHostModal
      open={open}
      onOpenChange={handleDialogOpenChange}
      size="4xl"
      // cqw: widths follow the space the side panel leaves, not the viewport.
      className="flex !h-[90vh] !max-h-[90vh] !min-h-[90vh] !w-[calc(100cqw-24px)] !max-w-[1192px] flex-col overflow-hidden p-4 sm:!w-[calc(100cqw-40px)] sm:p-6 lg:!w-[calc(100cqw-64px)] lg:p-8"
    >
      <DialogHeader className="gap-2 p-0">
        <DialogTitle className="text-lg font-semibold">
          {modalTitle}
        </DialogTitle>
      </DialogHeader>

      <div className="mt-6 flex min-h-0 flex-1 flex-col overflow-hidden lg:mt-8">
        <div className="flex min-h-0 flex-1 flex-col overflow-hidden lg:flex-row">
          {/* Help and progress share the left column, so the form keeps the height. */}
          <div className="mb-4 box-border flex w-full shrink-0 flex-col gap-4 lg:mb-0 lg:w-[328px] lg:gap-8">
            <LighthouseConnectHelp
              docsLink={docsLink}
              docsDestination={docsDestination}
              providerType={
                isProviderFlow ? providerTypeHint : organizationType
              }
              mode={mode}
              stepName={stepName}
              stepLabel={stepLabel}
              connectionMethod={connectionMethod}
              isOrganizationsFlow={!isProviderFlow}
            />
            <WizardStepper currentStep={stepperCurrent} steps={stepperSteps} />
          </div>
          <div
            aria-hidden
            className="hidden w-[100px] min-w-0 shrink lg:block"
          />

          <div className="relative flex min-h-0 flex-1 flex-col overflow-hidden">
            <div className="relative min-h-0 flex-1 overflow-hidden">
              <div
                ref={containerRef}
                className="minimal-scrollbar h-full w-full overflow-y-scroll [scrollbar-gutter:stable] lg:ml-auto lg:max-w-[620px] xl:max-w-[700px]"
              >
                {isProviderFlow &&
                  currentStep === PROVIDER_WIZARD_STEP.CONNECT && (
                    <ConnectStep
                      providerType={providerTypeHint}
                      locked={isDirectCredentialsEntry}
                      onProviderTypeChange={(providerType) => {
                        // The picker re-reports the same type on re-render; signal a pick once.
                        if (providerType && providerType !== providerTypeHint) {
                          dispatchProviderFunnel({
                            step: PROVIDER_FUNNEL_STEP.PROVIDER_TYPE_SELECTED,
                            providerType,
                          });
                        }
                        setProviderTypeHint(providerType);
                      }}
                      // The account is saved and tested: an update closes the
                      // wizard, an add moves on to the launch step.
                      onConnected={handleTestSuccess}
                      onClose={handleClose}
                      onSelectOrganizations={openOrganizationsFlow}
                      onFooterChange={setFooterConfig}
                    />
                  )}

                {isProviderFlow &&
                  currentStep === PROVIDER_WIZARD_STEP.LAUNCH && (
                    <LaunchStep
                      onBack={() =>
                        setCurrentStep(PROVIDER_WIZARD_STEP.CONNECT)
                      }
                      onClose={handleClose}
                      onFooterChange={setFooterConfig}
                      capability={resolvedScanScheduleCapability}
                      isScanLimitReached={isScanLimitReached}
                      isScheduleCapabilityLoading={isScheduleCapabilityLoading}
                    />
                  )}

                {!isProviderFlow &&
                  orgCurrentStep === ORG_WIZARD_STEP.SETUP &&
                  organizationType === ORGANIZATION_TYPE.AWS && (
                    <OrgSetupForm
                      onBack={
                        isOrgDirectEntry ? handleClose : backToProviderFlow
                      }
                      onSelectSingleAccount={
                        isOrgDirectEntry ? undefined : backToProviderFlow
                      }
                      onClose={handleClose}
                      onNext={() => {
                        setOrgCurrentStep(ORG_WIZARD_STEP.VALIDATE);
                      }}
                      onFooterChange={setFooterConfig}
                      onPhaseChange={setOrgSetupPhase}
                      initialPhase={orgSetupPhase}
                      initialValues={
                        orgInitialData
                          ? {
                              organizationName: orgInitialData.organizationName,
                              awsOrgId: orgInitialData.externalId,
                            }
                          : undefined
                      }
                      intent={orgInitialData?.intent}
                    />
                  )}

                {!isProviderFlow &&
                  orgCurrentStep === ORG_WIZARD_STEP.SETUP &&
                  organizationType === ORGANIZATION_TYPE.AZURE && (
                    <AzureOrgSetupForm
                      onBack={
                        isOrgDirectEntry ? handleClose : backToProviderFlow
                      }
                      onSelectSingleAccount={
                        isOrgDirectEntry ? undefined : backToProviderFlow
                      }
                      onNext={() => {
                        setOrgCurrentStep(ORG_WIZARD_STEP.VALIDATE);
                      }}
                      onFooterChange={setFooterConfig}
                      onPhaseChange={setOrgSetupPhase}
                      initialPhase={orgSetupPhase}
                      initialValues={
                        orgInitialData
                          ? {
                              organizationName: orgInitialData.organizationName,
                              tenantId: orgInitialData.externalId,
                            }
                          : undefined
                      }
                      intent={orgInitialData?.intent}
                    />
                  )}

                {!isProviderFlow &&
                  orgCurrentStep === ORG_WIZARD_STEP.SETUP &&
                  organizationType === ORGANIZATION_TYPE.GCP && (
                    <GcpOrgSetupForm
                      onBack={
                        isOrgDirectEntry ? handleClose : backToProviderFlow
                      }
                      onSelectSingleAccount={
                        isOrgDirectEntry ? undefined : backToProviderFlow
                      }
                      onClose={handleClose}
                      onNext={() => {
                        setOrgCurrentStep(ORG_WIZARD_STEP.VALIDATE);
                      }}
                      onFooterChange={setFooterConfig}
                      onPhaseChange={setOrgSetupPhase}
                      initialPhase={orgSetupPhase}
                      initialValues={
                        orgInitialData
                          ? {
                              organizationName: orgInitialData.organizationName,
                              gcpOrgId: orgInitialData.externalId,
                            }
                          : undefined
                      }
                      intent={orgInitialData?.intent}
                    />
                  )}

                {!isProviderFlow &&
                  orgCurrentStep === ORG_WIZARD_STEP.VALIDATE && (
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

                {!isProviderFlow &&
                  orgCurrentStep === ORG_WIZARD_STEP.LAUNCH && (
                    <OrgLaunchScan
                      onClose={handleClose}
                      onBack={() => {
                        setOrgCurrentStep(ORG_WIZARD_STEP.VALIDATE);
                      }}
                      onFooterChange={setFooterConfig}
                      capability={resolvedScanScheduleCapability}
                      isScanLimitReached={isScanLimitReached}
                      isScheduleCapabilityLoading={isScheduleCapabilityLoading}
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
                    disabled={
                      resolvedFooterConfig.actionDisabled ||
                      resolvedFooterConfig.actionLoading
                    }
                    aria-busy={resolvedFooterConfig.actionLoading || undefined}
                    onClick={
                      resolvedFooterConfig.actionType ===
                      WIZARD_FOOTER_ACTION_TYPE.BUTTON
                        ? resolvedFooterConfig.onAction
                        : undefined
                    }
                  >
                    {resolvedFooterConfig.actionLoading && (
                      <Loader2 aria-hidden className="animate-spin" />
                    )}
                    {resolvedFooterConfig.actionLabel}
                  </Button>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </SidePanelHostModal>
  );
}
