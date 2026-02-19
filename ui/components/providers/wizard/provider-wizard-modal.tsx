"use client";

import { ExternalLink, Info } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { OrgAccountSelection } from "@/components/providers/organizations/org-account-selection";
import { OrgConnectionTest } from "@/components/providers/organizations/org-connection-test";
import { OrgDiscoveryLoader } from "@/components/providers/organizations/org-discovery-loader";
import { OrgLaunchScan } from "@/components/providers/organizations/org-launch-scan";
import { OrgSetupForm } from "@/components/providers/organizations/org-setup-form";
import { Button } from "@/components/shadcn/button/button";
import { DialogHeader, DialogTitle } from "@/components/shadcn/dialog";
import { Modal } from "@/components/shadcn/modal";
import { getProviderHelpText } from "@/lib";
import { useOrgSetupStore } from "@/store/organizations/store";
import { useProviderWizardStore } from "@/store/provider-wizard/store";
import { ORG_WIZARD_STEP, OrgWizardStep } from "@/types/organizations";
import {
  PROVIDER_WIZARD_MODE,
  PROVIDER_WIZARD_STEP,
  ProviderWizardMode,
  ProviderWizardStep,
} from "@/types/provider-wizard";
import { ProviderType } from "@/types/providers";

import { ConnectStep } from "./steps/connect-step";
import { CredentialsStep } from "./steps/credentials-step";
import {
  WIZARD_FOOTER_ACTION_TYPE,
  WizardFooterConfig,
} from "./steps/footer-controls";
import { LaunchStep } from "./steps/launch-step";
import { TestConnectionStep } from "./steps/test-connection-step";
import { WizardStepper } from "./wizard-stepper";

const WIZARD_VARIANT = {
  PROVIDER: "provider",
  ORGANIZATIONS: "organizations",
} as const;

type WizardVariant = (typeof WIZARD_VARIANT)[keyof typeof WIZARD_VARIANT];

const VALIDATE_PHASE = {
  DISCOVERY: "discovery",
  SELECTION: "selection",
  TESTING: "testing",
} as const;

type ValidatePhase = (typeof VALIDATE_PHASE)[keyof typeof VALIDATE_PHASE];

const EMPTY_FOOTER_CONFIG: WizardFooterConfig = {
  showBack: false,
  backLabel: "Back",
  showAction: false,
  actionLabel: "Next",
  actionType: WIZARD_FOOTER_ACTION_TYPE.BUTTON,
};

export interface ProviderWizardInitialData {
  providerId: string;
  providerType: ProviderType;
  providerUid: string;
  providerAlias: string | null;
  secretId?: string | null;
  via?: string | null;
  mode?: ProviderWizardMode;
}

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
  const router = useRouter();
  const [wizardVariant, setWizardVariant] = useState<WizardVariant>(
    WIZARD_VARIANT.PROVIDER,
  );
  const [currentStep, setCurrentStep] = useState<ProviderWizardStep>(
    PROVIDER_WIZARD_STEP.CONNECT,
  );
  const [orgCurrentStep, setOrgCurrentStep] = useState<OrgWizardStep>(
    ORG_WIZARD_STEP.SETUP,
  );
  const [validatePhase, setValidatePhase] = useState<ValidatePhase>(
    VALIDATE_PHASE.DISCOVERY,
  );
  const [footerConfig, setFooterConfig] =
    useState<WizardFooterConfig>(EMPTY_FOOTER_CONFIG);
  const [providerTypeHint, setProviderTypeHint] = useState<ProviderType | null>(
    null,
  );

  const {
    reset: resetProviderWizard,
    setProvider,
    setVia,
    setSecretId,
    setMode,
    mode,
    providerType,
  } = useProviderWizardStore();
  const { connectionResults, reset: resetOrgWizard } = useOrgSetupStore();

  const hasConnectionErrors = Object.values(connectionResults).some(
    (status) => status === "error",
  );

  useEffect(() => {
    if (!open) {
      return;
    }

    if (initialData) {
      setWizardVariant(WIZARD_VARIANT.PROVIDER);
      setProvider({
        id: initialData.providerId,
        type: initialData.providerType,
        uid: initialData.providerUid,
        alias: initialData.providerAlias,
      });
      setVia(initialData.via || null);
      setSecretId(initialData.secretId || null);
      setMode(
        initialData.mode ||
          (initialData.secretId
            ? PROVIDER_WIZARD_MODE.UPDATE
            : PROVIDER_WIZARD_MODE.ADD),
      );
      setCurrentStep(PROVIDER_WIZARD_STEP.CREDENTIALS);
      setOrgCurrentStep(ORG_WIZARD_STEP.SETUP);
      setValidatePhase(VALIDATE_PHASE.DISCOVERY);
      setFooterConfig(EMPTY_FOOTER_CONFIG);
      setProviderTypeHint(initialData.providerType);
      return;
    }

    resetProviderWizard();
    resetOrgWizard();
    setWizardVariant(WIZARD_VARIANT.PROVIDER);
    setCurrentStep(PROVIDER_WIZARD_STEP.CONNECT);
    setOrgCurrentStep(ORG_WIZARD_STEP.SETUP);
    setValidatePhase(VALIDATE_PHASE.DISCOVERY);
    setFooterConfig(EMPTY_FOOTER_CONFIG);
    setProviderTypeHint(null);
  }, [
    initialData,
    open,
    resetOrgWizard,
    resetProviderWizard,
    setMode,
    setProvider,
    setSecretId,
    setVia,
  ]);

  const handleClose = () => {
    resetProviderWizard();
    resetOrgWizard();
    setWizardVariant(WIZARD_VARIANT.PROVIDER);
    setCurrentStep(PROVIDER_WIZARD_STEP.CONNECT);
    setOrgCurrentStep(ORG_WIZARD_STEP.SETUP);
    setValidatePhase(VALIDATE_PHASE.DISCOVERY);
    setFooterConfig(EMPTY_FOOTER_CONFIG);
    setProviderTypeHint(null);
    onOpenChange(false);
  };

  const handleDialogOpenChange = (nextOpen: boolean) => {
    if (nextOpen) {
      onOpenChange(true);
      return;
    }
    handleClose();
  };

  const handleTestSuccess = () => {
    if (mode === PROVIDER_WIZARD_MODE.UPDATE) {
      handleClose();
      return;
    }

    setCurrentStep(PROVIDER_WIZARD_STEP.LAUNCH);
  };

  const openOrganizationsFlow = () => {
    resetOrgWizard();
    setWizardVariant(WIZARD_VARIANT.ORGANIZATIONS);
    setOrgCurrentStep(ORG_WIZARD_STEP.SETUP);
    setValidatePhase(VALIDATE_PHASE.DISCOVERY);
    setFooterConfig(EMPTY_FOOTER_CONFIG);
    setProviderTypeHint(null);
  };

  const backToProviderFlow = () => {
    resetOrgWizard();
    setWizardVariant(WIZARD_VARIANT.PROVIDER);
    setCurrentStep(PROVIDER_WIZARD_STEP.CONNECT);
    setFooterConfig(EMPTY_FOOTER_CONFIG);
    setProviderTypeHint(null);
  };

  const isProviderFlow = wizardVariant === WIZARD_VARIANT.PROVIDER;
  const docsLink = getProviderHelpText(
    isProviderFlow ? (providerTypeHint ?? providerType ?? "") : "aws",
  ).link;
  const resolvedFooterConfig: WizardFooterConfig =
    isProviderFlow && currentStep === PROVIDER_WIZARD_STEP.LAUNCH
      ? {
          showBack: true,
          backLabel: "Back",
          onBack: () => setCurrentStep(PROVIDER_WIZARD_STEP.TEST),
          showAction: true,
          actionLabel: "Go to scans",
          actionType: WIZARD_FOOTER_ACTION_TYPE.BUTTON,
          onAction: () => {
            handleClose();
            router.push("/scans");
          },
        }
      : footerConfig;

  useEffect(() => {
    if (isProviderFlow) {
      return;
    }

    if (
      orgCurrentStep === ORG_WIZARD_STEP.VALIDATE &&
      validatePhase === VALIDATE_PHASE.DISCOVERY
    ) {
      setFooterConfig({
        showBack: true,
        backLabel: "Back",
        onBack: () => {
          setOrgCurrentStep(ORG_WIZARD_STEP.SETUP);
        },
        showAction: false,
        actionLabel: "Next",
        actionType: WIZARD_FOOTER_ACTION_TYPE.BUTTON,
      });
    }
  }, [isProviderFlow, orgCurrentStep, validatePhase]);

  return (
    <Modal
      open={open}
      onOpenChange={handleDialogOpenChange}
      size="4xl"
      className="flex !h-[90vh] !max-h-[90vh] !min-h-[90vh] !max-w-[60vw] !min-w-[70vw] flex-col overflow-hidden p-8"
    >
      <DialogHeader className="gap-2 p-0">
        <DialogTitle className="text-lg font-semibold">
          Adding A Cloud Provider
        </DialogTitle>
        <div className="text-muted-foreground flex items-center gap-2 text-sm">
          <Info className="size-4 shrink-0" />
          <span>For assistance connecting a Cloud Provider visit</span>
          <Button variant="link" size="link-sm" className="h-auto p-0" asChild>
            <a href={docsLink} target="_blank" rel="noopener noreferrer">
              <ExternalLink className="size-3.5 shrink-0" />
              <span>Prowler Docs</span>
            </a>
          </Button>
        </div>
      </DialogHeader>

      <div className="mt-8 flex min-h-0 flex-1 justify-between overflow-hidden">
        <div className="box-border w-[328px] shrink-0">
          {isProviderFlow ? (
            <WizardStepper currentStep={currentStep} />
          ) : (
            <WizardStepper
              currentStep={orgCurrentStep}
              stepOffset={1}
              hasConnectionErrors={hasConnectionErrors}
            />
          )}
        </div>

        <div className="flex-1 overflow-hidden">
          <div className="minimal-scrollbar ml-auto h-full w-full max-w-[620px] overflow-y-auto">
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
              <LaunchStep />
            )}

            {!isProviderFlow && orgCurrentStep === ORG_WIZARD_STEP.SETUP && (
              <OrgSetupForm
                onBack={backToProviderFlow}
                onNext={() => {
                  setOrgCurrentStep(ORG_WIZARD_STEP.VALIDATE);
                  setValidatePhase(VALIDATE_PHASE.DISCOVERY);
                }}
                onFooterChange={setFooterConfig}
              />
            )}

            {!isProviderFlow &&
              orgCurrentStep === ORG_WIZARD_STEP.VALIDATE &&
              validatePhase === VALIDATE_PHASE.DISCOVERY && (
                <OrgDiscoveryLoader
                  onDiscoveryComplete={() => {
                    setValidatePhase(VALIDATE_PHASE.SELECTION);
                  }}
                />
              )}

            {!isProviderFlow &&
              orgCurrentStep === ORG_WIZARD_STEP.VALIDATE &&
              validatePhase === VALIDATE_PHASE.SELECTION && (
                <OrgAccountSelection
                  onBack={() => {
                    setOrgCurrentStep(ORG_WIZARD_STEP.SETUP);
                  }}
                  onNext={() => {
                    setValidatePhase(VALIDATE_PHASE.TESTING);
                  }}
                  onFooterChange={setFooterConfig}
                />
              )}

            {!isProviderFlow &&
              orgCurrentStep === ORG_WIZARD_STEP.VALIDATE &&
              validatePhase === VALIDATE_PHASE.TESTING && (
                <OrgConnectionTest
                  onBack={() => {
                    setValidatePhase(VALIDATE_PHASE.SELECTION);
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
                  setValidatePhase(VALIDATE_PHASE.TESTING);
                }}
                onFooterChange={setFooterConfig}
              />
            )}
          </div>
        </div>
      </div>

      {(resolvedFooterConfig.showBack || resolvedFooterConfig.showAction) && (
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
            <div>
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
