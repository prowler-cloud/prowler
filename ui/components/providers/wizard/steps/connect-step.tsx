"use client";

import { useEffect, useRef, useState } from "react";

import {
  ConnectAccountForm,
  ConnectAccountSuccessData,
} from "@/components/providers/workflow/forms";
import { useProviderWizardStore } from "@/store/provider-wizard/store";
import { PROVIDER_WIZARD_MODE } from "@/types/provider-wizard";
import { ProviderType } from "@/types/providers";

import {
  WIZARD_FOOTER_ACTION_TYPE,
  WizardFooterConfig,
} from "./footer-controls";

interface ConnectStepProps {
  onNext: () => void;
  onSelectOrganizations: () => void;
  onFooterChange: (config: WizardFooterConfig) => void;
  onProviderTypeChange: (providerType: ProviderType | null) => void;
}

export function ConnectStep({
  onNext,
  onSelectOrganizations,
  onFooterChange,
  onProviderTypeChange,
}: ConnectStepProps) {
  const { setProvider, setVia, setSecretId, setMode } =
    useProviderWizardStore();
  const backHandlerRef = useRef<(() => void) | null>(null);
  const [uiState, setUiState] = useState({
    showBack: false,
    showAction: false,
    actionLabel: "Next",
    actionDisabled: true,
    isLoading: false,
  });

  const formId = "provider-wizard-connect-form";

  const handleSuccess = (data: ConnectAccountSuccessData) => {
    setProvider({
      id: data.id,
      type: data.providerType,
      uid: data.uid,
      alias: data.alias,
    });
    setVia(null);
    setSecretId(null);
    setMode(PROVIDER_WIZARD_MODE.ADD);
    onNext();
  };

  useEffect(() => {
    onFooterChange({
      showBack: uiState.showBack,
      backLabel: "Back",
      backDisabled: uiState.isLoading,
      onBack: () => backHandlerRef.current?.(),
      showAction: uiState.showAction,
      actionLabel: uiState.actionLabel,
      actionDisabled: uiState.actionDisabled || uiState.isLoading,
      actionType: WIZARD_FOOTER_ACTION_TYPE.SUBMIT,
      actionFormId: formId,
    });
  }, [onFooterChange, uiState]);

  return (
    <ConnectAccountForm
      formId={formId}
      hideNavigation
      onSuccess={handleSuccess}
      onSelectOrganizations={onSelectOrganizations}
      onProviderTypeChange={onProviderTypeChange}
      onUiStateChange={setUiState}
      onBackHandlerChange={(handler) => {
        backHandlerRef.current = handler;
      }}
    />
  );
}
