"use client";

import { useRouter } from "next/navigation";
import {
  type Dispatch,
  type SetStateAction,
  useEffect,
  useRef,
  useState,
} from "react";

import { DOCS_URLS, getProviderHelpText } from "@/lib/external-urls";
import { isCloud } from "@/lib/shared/env";
import { endActiveTour } from "@/lib/tours/use-driver-tour";
import { useOnboardingCheckpointStore } from "@/store/onboarding-checkpoint";
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
import type { OrgWizardInitialData, ProviderWizardInitialData } from "../types";

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

function isSameFooterConfig(
  current: WizardFooterConfig,
  next: WizardFooterConfig,
) {
  return (
    current.showBack === next.showBack &&
    current.backLabel === next.backLabel &&
    Boolean(current.backDisabled) === Boolean(next.backDisabled) &&
    Boolean(current.showSecondaryAction) ===
      Boolean(next.showSecondaryAction) &&
    (current.secondaryActionLabel ?? "") ===
      (next.secondaryActionLabel ?? "") &&
    Boolean(current.secondaryActionDisabled) ===
      Boolean(next.secondaryActionDisabled) &&
    current.secondaryActionVariant === next.secondaryActionVariant &&
    current.secondaryActionType === next.secondaryActionType &&
    (current.secondaryActionFormId ?? "") ===
      (next.secondaryActionFormId ?? "") &&
    current.showAction === next.showAction &&
    current.actionLabel === next.actionLabel &&
    Boolean(current.actionDisabled) === Boolean(next.actionDisabled) &&
    current.actionType === next.actionType &&
    (current.actionFormId ?? "") === (next.actionFormId ?? "")
  );
}

interface UseProviderWizardControllerProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  initialData?: ProviderWizardInitialData;
  orgInitialData?: OrgWizardInitialData;
  // When false, skips post-close router.refresh() — caller relies on revalidatePath instead.
  refreshOnClose?: boolean;
}

export function useProviderWizardController({
  open,
  onOpenChange,
  initialData,
  orgInitialData,
  refreshOnClose = true,
}: UseProviderWizardControllerProps) {
  const router = useRouter();
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
  const [footerConfig, setFooterConfigState] =
    useState<WizardFooterConfig>(EMPTY_FOOTER_CONFIG);
  const footerConfigRef = useRef<WizardFooterConfig>(EMPTY_FOOTER_CONFIG);
  const footerActionCallbacksRef = useRef({
    onBack: () => footerConfigRef.current.onBack?.(),
    onSecondaryAction: () => footerConfigRef.current.onSecondaryAction?.(),
    onAction: () => footerConfigRef.current.onAction?.(),
  });
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
  const { reset: resetOrgWizard, setOrganization } = useOrgSetupStore();

  useEffect(() => {
    if (!open) {
      hasHydratedForCurrentOpenRef.current = false;
      return;
    }

    if (hasHydratedForCurrentOpenRef.current) {
      return;
    }
    hasHydratedForCurrentOpenRef.current = true;

    if (orgInitialData) {
      setWizardVariant(WIZARD_VARIANT.ORGANIZATIONS);
      resetOrgWizard();
      setOrganization(
        orgInitialData.organizationId,
        orgInitialData.organizationName,
        orgInitialData.externalId,
      );
      setOrgCurrentStep(orgInitialData.targetStep);
      setOrgSetupPhase(orgInitialData.targetPhase);
      footerConfigRef.current = EMPTY_FOOTER_CONFIG;
      setFooterConfigState(EMPTY_FOOTER_CONFIG);
      setProviderTypeHint(null);
      return;
    }

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
      footerConfigRef.current = EMPTY_FOOTER_CONFIG;
      setFooterConfigState(EMPTY_FOOTER_CONFIG);
      setProviderTypeHint(initialProviderType);
      setOrgSetupPhase(ORG_SETUP_PHASE.DETAILS);
      return;
    }

    resetProviderWizard();
    resetOrgWizard();
    setWizardVariant(WIZARD_VARIANT.PROVIDER);
    setCurrentStep(PROVIDER_WIZARD_STEP.CONNECT);
    setOrgCurrentStep(ORG_WIZARD_STEP.SETUP);
    footerConfigRef.current = EMPTY_FOOTER_CONFIG;
    setFooterConfigState(EMPTY_FOOTER_CONFIG);
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
    orgInitialData,
    resetOrgWizard,
    resetProviderWizard,
    setMode,
    setOrganization,
    setProvider,
    setSecretId,
    setVia,
  ]);

  const isOrgDirectEntry = Boolean(orgInitialData);

  const handleClose = () => {
    // Closing the wizard at any point ends the add-provider tour; the checkpoint
    // logic below still drives the handoff to scans. No-op off-onboarding.
    endActiveTour();

    // Read providerId before reset clears it — non-null means a provider was connected.
    const connectedProviderId = useProviderWizardStore.getState().providerId;

    resetProviderWizard();
    resetOrgWizard();
    setWizardVariant(WIZARD_VARIANT.PROVIDER);
    setCurrentStep(PROVIDER_WIZARD_STEP.CONNECT);
    setOrgCurrentStep(ORG_WIZARD_STEP.SETUP);
    footerConfigRef.current = EMPTY_FOOTER_CONFIG;
    setFooterConfigState(EMPTY_FOOTER_CONFIG);
    setProviderTypeHint(null);
    setOrgSetupPhase(ORG_SETUP_PHASE.DETAILS);
    onOpenChange(false);

    // Cloud-only; only fires if the store is armed (user started onboarding).
    if (isCloud()) {
      useOnboardingCheckpointStore.getState().requestOpenOnWizardClose({
        providerConnected: connectedProviderId !== null,
      });
    }

    if (refreshOnClose) {
      router.refresh();
    }
  };

  const handleDialogOpenChange = (nextOpen: boolean) => {
    if (nextOpen) {
      onOpenChange(true);
      return;
    }
    handleClose();
  };

  const handleTestSuccess = () => {
    setCurrentStep(PROVIDER_WIZARD_STEP.LAUNCH);
  };

  const updateFooterConfig: Dispatch<SetStateAction<WizardFooterConfig>> = (
    nextFooterConfig,
  ) => {
    const currentFooterConfig = footerConfigRef.current;
    const resolvedNextFooterConfig =
      typeof nextFooterConfig === "function"
        ? nextFooterConfig(currentFooterConfig)
        : nextFooterConfig;
    footerConfigRef.current = resolvedNextFooterConfig;

    if (isSameFooterConfig(currentFooterConfig, resolvedNextFooterConfig)) {
      return;
    }

    setFooterConfigState({
      ...resolvedNextFooterConfig,
      ...footerActionCallbacksRef.current,
    });
  };

  const openOrganizationsFlow = () => {
    // AWS Organizations diverges from the credentials path the tour guides toward; end
    // it so it doesn't dangle on a step that no longer fits. No-op off-onboarding.
    endActiveTour();
    resetOrgWizard();
    setWizardVariant(WIZARD_VARIANT.ORGANIZATIONS);
    setOrgCurrentStep(ORG_WIZARD_STEP.SETUP);
    footerConfigRef.current = EMPTY_FOOTER_CONFIG;
    setFooterConfigState(EMPTY_FOOTER_CONFIG);
    setProviderTypeHint(null);
    setOrgSetupPhase(ORG_SETUP_PHASE.DETAILS);
  };

  const backToProviderFlow = () => {
    resetOrgWizard();
    setWizardVariant(WIZARD_VARIANT.PROVIDER);
    setCurrentStep(PROVIDER_WIZARD_STEP.CONNECT);
    footerConfigRef.current = EMPTY_FOOTER_CONFIG;
    setFooterConfigState(EMPTY_FOOTER_CONFIG);
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
    isOrgDirectEntry,
    isProviderFlow,
    mode,
    modalTitle,
    openOrganizationsFlow,
    orgCurrentStep,
    orgSetupPhase,
    providerTypeHint,
    resolvedFooterConfig,
    setCurrentStep,
    setFooterConfig: updateFooterConfig,
    setOrgCurrentStep,
    setOrgSetupPhase,
    setProviderTypeHint,
    backToProviderFlow,
    wizardVariant,
  };
}
