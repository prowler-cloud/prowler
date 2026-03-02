"use client";

import { useEffect, useRef, useState } from "react";

import { DOCS_URLS, getProviderHelpText } from "@/lib/external-urls";
import { useOrgSetupStore } from "@/store/organizations/store";
import { useProviderWizardStore } from "@/store/provider-wizard/store";
import {
  ORG_SETUP_PHASE,
  ORG_WIZARD_STEP,
  OrgSetupPhase,
  OrgWizardStep,
} from "@/types/organizations";
import {
  PROVIDER_WIZARD_MODE,
  PROVIDER_WIZARD_STEP,
  ProviderWizardStep,
} from "@/types/provider-wizard";
import { ProviderType } from "@/types/providers";

import { getProviderWizardModalTitle } from "../provider-wizard-modal.utils";
import {
  WIZARD_FOOTER_ACTION_TYPE,
  WizardFooterConfig,
} from "../steps/footer-controls";
import type { ProviderWizardInitialData } from "../types";

const WIZARD_VARIANT = {
  PROVIDER: "provider",
  ORGANIZATIONS: "organizations",
} as const;

type WizardVariant = (typeof WIZARD_VARIANT)[keyof typeof WIZARD_VARIANT];

const EMPTY_FOOTER_CONFIG: WizardFooterConfig = {
  showBack: false,
  backLabel: "Back",
  showSecondaryAction: false,
  secondaryActionLabel: "",
  secondaryActionVariant: "outline",
  secondaryActionType: WIZARD_FOOTER_ACTION_TYPE.BUTTON,
  showAction: false,
  actionLabel: "Next",
  actionType: WIZARD_FOOTER_ACTION_TYPE.BUTTON,
};

interface UseProviderWizardControllerProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  initialData?: ProviderWizardInitialData;
}

export function useProviderWizardController({
  open,
  onOpenChange,
  initialData,
}: UseProviderWizardControllerProps) {
  const initialProviderId = initialData?.providerId ?? null;
  const initialProviderType = initialData?.providerType ?? null;
  const initialProviderUid = initialData?.providerUid ?? null;
  const initialProviderAlias = initialData?.providerAlias ?? null;
  const initialSecretId = initialData?.secretId ?? null;
  const initialVia = initialData?.via ?? null;
  const initialMode = initialData?.mode ?? null;
  const hasHydratedForCurrentOpenRef = useRef(false);
  const [wizardVariant, setWizardVariant] = useState<WizardVariant>(
    WIZARD_VARIANT.PROVIDER,
  );
  const [currentStep, setCurrentStep] = useState<ProviderWizardStep>(
    PROVIDER_WIZARD_STEP.CONNECT,
  );
  const [orgCurrentStep, setOrgCurrentStep] = useState<OrgWizardStep>(
    ORG_WIZARD_STEP.SETUP,
  );
  const [footerConfig, setFooterConfig] =
    useState<WizardFooterConfig>(EMPTY_FOOTER_CONFIG);
  const [providerTypeHint, setProviderTypeHint] = useState<ProviderType | null>(
    null,
  );
  const [orgSetupPhase, setOrgSetupPhase] = useState<OrgSetupPhase>(
    ORG_SETUP_PHASE.DETAILS,
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
  const { reset: resetOrgWizard } = useOrgSetupStore();

  useEffect(() => {
    if (!open) {
      hasHydratedForCurrentOpenRef.current = false;
      return;
    }

    if (hasHydratedForCurrentOpenRef.current) {
      return;
    }
    hasHydratedForCurrentOpenRef.current = true;

    if (initialProviderId && initialProviderType && initialProviderUid) {
      setWizardVariant(WIZARD_VARIANT.PROVIDER);
      setProvider({
        id: initialProviderId,
        type: initialProviderType,
        uid: initialProviderUid,
        alias: initialProviderAlias,
      });
      setVia(initialVia);
      setSecretId(initialSecretId);
      setMode(
        initialMode ||
          (initialSecretId
            ? PROVIDER_WIZARD_MODE.UPDATE
            : PROVIDER_WIZARD_MODE.ADD),
      );
      setCurrentStep(PROVIDER_WIZARD_STEP.CREDENTIALS);
      setOrgCurrentStep(ORG_WIZARD_STEP.SETUP);
      setFooterConfig(EMPTY_FOOTER_CONFIG);
      setProviderTypeHint(initialProviderType);
      setOrgSetupPhase(ORG_SETUP_PHASE.DETAILS);
      return;
    }

    resetProviderWizard();
    resetOrgWizard();
    setWizardVariant(WIZARD_VARIANT.PROVIDER);
    setCurrentStep(PROVIDER_WIZARD_STEP.CONNECT);
    setOrgCurrentStep(ORG_WIZARD_STEP.SETUP);
    setFooterConfig(EMPTY_FOOTER_CONFIG);
    setProviderTypeHint(null);
    setOrgSetupPhase(ORG_SETUP_PHASE.DETAILS);
  }, [
    initialMode,
    initialProviderAlias,
    initialProviderId,
    initialProviderType,
    initialProviderUid,
    initialSecretId,
    initialVia,
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
    setFooterConfig(EMPTY_FOOTER_CONFIG);
    setProviderTypeHint(null);
    setOrgSetupPhase(ORG_SETUP_PHASE.DETAILS);
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
    setFooterConfig(EMPTY_FOOTER_CONFIG);
    setProviderTypeHint(null);
    setOrgSetupPhase(ORG_SETUP_PHASE.DETAILS);
  };

  const backToProviderFlow = () => {
    resetOrgWizard();
    setWizardVariant(WIZARD_VARIANT.PROVIDER);
    setCurrentStep(PROVIDER_WIZARD_STEP.CONNECT);
    setFooterConfig(EMPTY_FOOTER_CONFIG);
    setProviderTypeHint(null);
    setOrgSetupPhase(ORG_SETUP_PHASE.DETAILS);
  };

  const isProviderFlow = wizardVariant === WIZARD_VARIANT.PROVIDER;
  const docsLink = isProviderFlow
    ? getProviderHelpText(providerTypeHint ?? providerType ?? "").link
    : DOCS_URLS.AWS_ORGANIZATIONS;
  const resolvedFooterConfig: WizardFooterConfig = footerConfig;
  const modalTitle = getProviderWizardModalTitle(mode);

  return {
    currentStep,
    docsLink,
    footerConfig,
    handleClose,
    handleDialogOpenChange,
    handleTestSuccess,
    isProviderFlow,
    modalTitle,
    openOrganizationsFlow,
    orgCurrentStep,
    orgSetupPhase,
    providerTypeHint,
    resolvedFooterConfig,
    setCurrentStep,
    setFooterConfig,
    setOrgCurrentStep,
    setOrgSetupPhase,
    setProviderTypeHint,
    backToProviderFlow,
    wizardVariant,
  };
}
