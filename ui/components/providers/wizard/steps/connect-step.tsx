"use client";

import { useEffect, useRef, useState } from "react";

import {
  ConnectAccountForm,
  ConnectAccountSuccessData,
} from "@/components/providers/workflow/forms";
import { endActiveTour } from "@/lib/tours/use-driver-tour";
import { useProviderWizardStore } from "@/store/provider-wizard/store";
import { useUIStore } from "@/store/ui/store";
import { ORGANIZATION_TYPE, OrgFlowType } from "@/types/organizations";
import { PROVIDER_WIZARD_MODE } from "@/types/provider-wizard";
import { ProviderType } from "@/types/providers";

import { AwsConnectStep } from "./aws/aws-connect-step";
import {
  WIZARD_FOOTER_ACTION_TYPE,
  WizardFooterConfig,
} from "./footer-controls";

interface ConnectStepProps {
  onNext: () => void;
  /** AWS registers the account and its credentials in this step, so it skips ahead. */
  onCredentialsSaved: () => void;
  onSelectOrganizations: (orgType: OrgFlowType) => void;
  onFooterChange: (config: WizardFooterConfig) => void;
  onProviderTypeChange: (providerType: ProviderType | null) => void;
  /** Provider the user was already working with, e.g. when returning from the AWS organization flow. */
  initialProviderType?: ProviderType | null;
}

export function ConnectStep({
  onNext,
  onCredentialsSaved,
  onSelectOrganizations,
  onFooterChange,
  onProviderTypeChange,
  initialProviderType = null,
}: ConnectStepProps) {
  const { setProvider, setVia, setSecretId, setMode } =
    useProviderWizardStore();
  const backHandlerRef = useRef<(() => void) | null>(null);
  // Local state needed: AWS swaps the generic account form for its one-step form.
  const [isAwsFlow, setIsAwsFlow] = useState(initialProviderType === "aws");
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
    // The layout only re-counts providers on a server render; flip the shared flag now.
    useUIStore.getState().setHasProviders(true);
    onNext();
  };

  useEffect(() => {
    // The footer sits outside the tour's spotlight, so once the user can continue
    // the tour has done its job and gets out of the way. No-op off-onboarding.
    if (uiState.showAction && !uiState.actionDisabled && !uiState.isLoading) {
      endActiveTour();
    }
    onFooterChange({
      showBack: uiState.showBack,
      backLabel: "Back",
      backDisabled: uiState.isLoading,
      // Leaving AWS remounts the generic form on a fresh provider list.
      onBack: isAwsFlow
        ? () => setIsAwsFlow(false)
        : () => backHandlerRef.current?.(),
      showAction: uiState.showAction,
      actionLabel: uiState.actionLabel,
      actionLoading: uiState.isLoading,
      actionDisabled: uiState.actionDisabled || uiState.isLoading,
      actionType: WIZARD_FOOTER_ACTION_TYPE.SUBMIT,
      actionFormId: formId,
    });
  }, [isAwsFlow, onFooterChange, uiState]);

  const handleProviderTypeChange = (providerType: ProviderType | null) => {
    onProviderTypeChange(providerType);
    if (providerType === "aws") setIsAwsFlow(true);
  };

  if (isAwsFlow) {
    return (
      <AwsConnectStep
        formId={formId}
        onConnected={onCredentialsSaved}
        onSelectOrganizations={() =>
          onSelectOrganizations(ORGANIZATION_TYPE.AWS)
        }
        onUiStateChange={setUiState}
      />
    );
  }

  return (
    <ConnectAccountForm
      formId={formId}
      hideNavigation
      onSuccess={handleSuccess}
      onSelectOrganizations={onSelectOrganizations}
      onProviderTypeChange={handleProviderTypeChange}
      onUiStateChange={setUiState}
      onBackHandlerChange={(handler) => {
        backHandlerRef.current = handler;
      }}
    />
  );
}
