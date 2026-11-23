"use client";

import { useEffect, useRef, useState } from "react";

import { ProviderPicker } from "@/components/providers/workflow/forms";
import type { OrgFlowType } from "@/types/organizations";
import type { ProviderType } from "@/types/providers";

import { ProviderConnectStep } from "./connect/provider-connect-step";
import { CONNECT_ACTION_KIND, type ConnectUiState } from "./connect/types";
import {
  WIZARD_FOOTER_ACTION_TYPE,
  WizardFooterConfig,
} from "./footer-controls";

const FORM_ID = "provider-wizard-connect-form";

const PICKER_UI_STATE: ConnectUiState = {
  showBack: false,
  showAction: false,
  actionLabel: "",
  actionDisabled: true,
  isLoading: false,
};

interface ConnectStepProps {
  /** The provider being connected; null while the user is still picking one. */
  providerType: ProviderType | null;
  /** The wizard was opened on an existing account: only its credentials change. */
  locked: boolean;
  onProviderTypeChange: (providerType: ProviderType | null) => void;
  /** The account is saved and its connection test passed. */
  onConnected: () => void;
  /** The footer offers it once a teammate has been invited instead, or to cancel an update. */
  onClose: () => void;
  onSelectOrganizations: (orgType: OrgFlowType) => void;
  onFooterChange: (config: WizardFooterConfig) => void;
}

/** Pick a provider, then connect it: account, credentials and test in one step. */
export function ConnectStep({
  providerType,
  locked,
  onProviderTypeChange,
  onConnected,
  onClose,
  onSelectOrganizations,
  onFooterChange,
}: ConnectStepProps) {
  // Local state needed: the active form publishes what the footer shows.
  const [uiState, setUiState] = useState<ConnectUiState>(PICKER_UI_STATE);
  // The modal hands over fresh callbacks every render; the footer effect keeps
  // one closure and reads the latest through refs.
  const closeRef = useRef(onClose);
  const providerChangeRef = useRef(onProviderTypeChange);
  // Synced after render: render must not write refs.
  useEffect(() => {
    closeRef.current = onClose;
    providerChangeRef.current = onProviderTypeChange;
  }, [onClose, onProviderTypeChange]);

  const isPicking = providerType === null;

  useEffect(() => {
    if (isPicking) {
      onFooterChange({
        showBack: false,
        backLabel: "Back",
        showAction: false,
        actionLabel: "",
        actionType: WIZARD_FOOTER_ACTION_TYPE.BUTTON,
      });
      return;
    }
    // Nothing left to submit once a teammate has been invited: the action closes.
    const closes = uiState.actionKind === CONNECT_ACTION_KIND.CLOSE;
    onFooterChange({
      showBack: uiState.showBack,
      // An account opened from the list has nothing to go back to.
      backLabel: locked ? "Cancel" : "Back",
      backDisabled: uiState.isLoading,
      onBack: locked
        ? () => closeRef.current()
        : () => providerChangeRef.current(null),
      showAction: uiState.showAction,
      actionLabel: uiState.actionLabel,
      actionLoading: uiState.isLoading,
      actionDisabled: uiState.actionDisabled || uiState.isLoading,
      actionType: closes
        ? WIZARD_FOOTER_ACTION_TYPE.BUTTON
        : WIZARD_FOOTER_ACTION_TYPE.SUBMIT,
      actionFormId: closes ? undefined : FORM_ID,
      onAction: closes ? () => closeRef.current() : undefined,
    });
  }, [isPicking, locked, onFooterChange, uiState]);

  if (isPicking) {
    return <ProviderPicker onProviderTypeChange={onProviderTypeChange} />;
  }

  return (
    <ProviderConnectStep
      // A different provider starts from a fresh form and footer.
      key={providerType}
      providerType={providerType}
      formId={FORM_ID}
      locked={locked}
      onConnected={onConnected}
      onSelectOrganizations={onSelectOrganizations}
      onUiStateChange={setUiState}
    />
  );
}
