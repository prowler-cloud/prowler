"use client";

import { useEffect } from "react";

import {
  WIZARD_FOOTER_ACTION_TYPE,
  WizardFooterConfig,
} from "@/components/providers/wizard/steps/footer-controls";

interface OrgAccountSelectionProps {
  onBack: () => void;
  onNext: () => void;
  onSkip: () => void;
  onFooterChange: (config: WizardFooterConfig) => void;
}

export function OrgAccountSelection({
  onBack,
  onNext,
  onSkip,
  onFooterChange,
}: OrgAccountSelectionProps) {
  useEffect(() => {
    onFooterChange({
      showBack: true,
      backLabel: "Back",
      onBack,
      showSecondaryAction: true,
      secondaryActionLabel: "Skip",
      secondaryActionType: WIZARD_FOOTER_ACTION_TYPE.BUTTON,
      onSecondaryAction: onSkip,
      showAction: true,
      actionLabel: "Continue",
      actionType: WIZARD_FOOTER_ACTION_TYPE.BUTTON,
      onAction: onNext,
    });
  }, [onBack, onFooterChange, onNext, onSkip]);

  return (
    <div className="flex min-h-0 flex-1 flex-col justify-center gap-2 py-6">
      <h3 className="text-base font-semibold">Account selection</h3>
      <p className="text-muted-foreground text-sm">
        Account discovery and selection are introduced in the next chained PR.
      </p>
    </div>
  );
}
