"use client";

import { useEffect } from "react";

import {
  WIZARD_FOOTER_ACTION_TYPE,
  WizardFooterConfig,
} from "@/components/providers/wizard/steps/footer-controls";
import { ORG_SETUP_PHASE, OrgSetupPhase } from "@/types/organizations";

interface OrgSetupFormProps {
  onBack: () => void;
  onNext: () => void;
  onFooterChange: (config: WizardFooterConfig) => void;
  onPhaseChange: (phase: OrgSetupPhase) => void;
  initialPhase?: OrgSetupPhase;
}

export function OrgSetupForm({
  onBack,
  onNext,
  onFooterChange,
  onPhaseChange,
  initialPhase = ORG_SETUP_PHASE.DETAILS,
}: OrgSetupFormProps) {
  useEffect(() => {
    onPhaseChange(initialPhase);
  }, [initialPhase, onPhaseChange]);

  useEffect(() => {
    onFooterChange({
      showBack: true,
      backLabel: "Back",
      onBack,
      showAction: true,
      actionLabel: "Continue",
      actionType: WIZARD_FOOTER_ACTION_TYPE.BUTTON,
      onAction: onNext,
    });
  }, [onBack, onFooterChange, onNext]);

  return (
    <div className="flex min-h-0 flex-1 flex-col justify-center gap-2 py-6">
      <h3 className="text-base font-semibold">AWS Organizations</h3>
      <p className="text-muted-foreground text-sm">
        The full AWS Organizations setup step is included in the next chained
        PR.
      </p>
    </div>
  );
}
