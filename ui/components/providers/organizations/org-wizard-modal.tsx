"use client";

import { ExternalLink } from "lucide-react";
import { useState } from "react";

import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/shadcn/dialog";
import { useOrgSetupStore } from "@/store/organizations/store";
import { ORG_WIZARD_STEP, OrgWizardStep } from "@/types/organizations";

import { OrgAccountSelection } from "./org-account-selection";
import { OrgConnectionTest } from "./org-connection-test";
import { OrgDiscoveryLoader } from "./org-discovery-loader";
import { OrgLaunchScan } from "./org-launch-scan";
import { OrgSetupForm } from "./org-setup-form";
import { OrgWizardStepper } from "./org-wizard-stepper";

const VALIDATE_PHASE = {
  DISCOVERY: "discovery",
  SELECTION: "selection",
  TESTING: "testing",
} as const;

type ValidatePhase = (typeof VALIDATE_PHASE)[keyof typeof VALIDATE_PHASE];

interface OrgWizardModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function OrgWizardModal({ open, onOpenChange }: OrgWizardModalProps) {
  const [currentStep, setCurrentStep] = useState<OrgWizardStep>(
    ORG_WIZARD_STEP.SETUP,
  );
  const [validatePhase, setValidatePhase] = useState<ValidatePhase>(
    VALIDATE_PHASE.DISCOVERY,
  );

  const { connectionResults, reset } = useOrgSetupStore();

  const hasConnectionErrors = Object.values(connectionResults).some(
    (s) => s === "error",
  );

  const handleClose = () => {
    reset();
    setCurrentStep(ORG_WIZARD_STEP.SETUP);
    setValidatePhase(VALIDATE_PHASE.DISCOVERY);
    onOpenChange(false);
  };

  const handleSetupBack = () => {
    handleClose();
  };

  const handleSetupNext = () => {
    setCurrentStep(ORG_WIZARD_STEP.VALIDATE);
    setValidatePhase(VALIDATE_PHASE.DISCOVERY);
  };

  const handleDiscoveryComplete = () => {
    setValidatePhase(VALIDATE_PHASE.SELECTION);
  };

  const handleSelectionBack = () => {
    // Go back to setup form
    setCurrentStep(ORG_WIZARD_STEP.SETUP);
  };

  const handleSelectionNext = () => {
    setValidatePhase(VALIDATE_PHASE.TESTING);
  };

  const handleTestingBack = () => {
    setValidatePhase(VALIDATE_PHASE.SELECTION);
  };

  const handleTestingNext = () => {
    setCurrentStep(ORG_WIZARD_STEP.LAUNCH);
  };

  const handleSkipValidation = () => {
    setCurrentStep(ORG_WIZARD_STEP.LAUNCH);
  };

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="max-w-4xl p-0">
        <DialogHeader className="border-b px-6 py-4">
          <div className="flex items-center justify-between">
            <DialogTitle className="text-lg font-semibold">
              Adding A Cloud Provider
            </DialogTitle>
            <a
              href="https://docs.prowler.com"
              target="_blank"
              rel="noopener noreferrer"
              className="text-muted-foreground hover:text-foreground flex items-center gap-1 text-xs"
            >
              Learn more
              <ExternalLink className="size-3" />
            </a>
          </div>
        </DialogHeader>

        <div className="flex min-h-[500px]">
          {/* Left: Stepper */}
          <div className="w-72 shrink-0 border-r p-5">
            <OrgWizardStepper
              currentStep={currentStep}
              hasConnectionErrors={hasConnectionErrors}
            />
          </div>

          {/* Right: Step content */}
          <div className="flex-1 overflow-y-auto p-6">
            {currentStep === ORG_WIZARD_STEP.SETUP && (
              <OrgSetupForm onBack={handleSetupBack} onNext={handleSetupNext} />
            )}

            {currentStep === ORG_WIZARD_STEP.VALIDATE &&
              validatePhase === VALIDATE_PHASE.DISCOVERY && (
                <OrgDiscoveryLoader
                  onDiscoveryComplete={handleDiscoveryComplete}
                />
              )}

            {currentStep === ORG_WIZARD_STEP.VALIDATE &&
              validatePhase === VALIDATE_PHASE.SELECTION && (
                <OrgAccountSelection
                  onBack={handleSelectionBack}
                  onNext={handleSelectionNext}
                />
              )}

            {currentStep === ORG_WIZARD_STEP.VALIDATE &&
              validatePhase === VALIDATE_PHASE.TESTING && (
                <OrgConnectionTest
                  onBack={handleTestingBack}
                  onNext={handleTestingNext}
                  onSkip={handleSkipValidation}
                />
              )}

            {currentStep === ORG_WIZARD_STEP.LAUNCH && (
              <OrgLaunchScan onClose={handleClose} />
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
