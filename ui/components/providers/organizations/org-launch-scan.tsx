"use client";

import { useEffect } from "react";

import {
  WIZARD_FOOTER_ACTION_TYPE,
  WizardFooterConfig,
} from "@/components/providers/wizard/steps/footer-controls";

interface OrgLaunchScanProps {
  onClose: () => void;
  onBack: () => void;
  onFooterChange: (config: WizardFooterConfig) => void;
}

export function OrgLaunchScan({
  onClose,
  onBack,
  onFooterChange,
}: OrgLaunchScanProps) {
  useEffect(() => {
    onFooterChange({
      showBack: true,
      backLabel: "Back",
      onBack,
      showAction: true,
      actionLabel: "Close",
      actionType: WIZARD_FOOTER_ACTION_TYPE.BUTTON,
      onAction: onClose,
    });
  }, [onBack, onClose, onFooterChange]);

  return (
    <div className="flex min-h-0 flex-1 flex-col justify-center gap-2 py-6">
      <h3 className="text-base font-semibold">Launch scan</h3>
      <p className="text-muted-foreground text-sm">
        Organizations scan launch flow is completed in the next chained PR.
      </p>
    </div>
  );
}
