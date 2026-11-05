"use client";

import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { DOCS_URLS, getProviderHelpText } from "@/lib/external-urls";
import {
  dispatchProviderFunnel,
  PROVIDER_FUNNEL_METHOD,
  PROVIDER_FUNNEL_STEP,
} from "@/lib/provider-funnel/provider-funnel-events";
import { useOrgSetupStore } from "@/store/organizations/store";
import { useProviderWizardStore } from "@/store/provider-wizard/store";
import {
  ORG_SETUP_PHASE,
  ORG_WIZARD_STEP,
  ORGANIZATION_TYPE,
  OrgFlowType,
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
import { resolveConnectMethod } from "../steps/connect/connect-methods";
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

const ORG_DOCS_URL = {
  [ORGANIZATION_TYPE.AWS]: DOCS_URLS.AWS_ORGANIZATIONS,
  [ORGANIZATION_TYPE.AZURE]: DOCS_URLS.AZURE_ORGANIZATIONS,
  [ORGANIZATION_TYPE.GCP]: DOCS_URLS.GCP_ORGANIZATIONS,
} as const satisfies Record<OrgFlowType, string>;

// Stable names for the abandonment signal; the numeric step ids are not a contract.
const PROVIDER_STEP_NAME = {
  [PROVIDER_WIZARD_STEP.CONNECT]: "connect",
  [PROVIDER_WIZARD_STEP.LAUNCH]: "launch",
} as const satisfies Record<ProviderWizardStep, string>;

const ORG_STEP_NAME = {
  [ORG_WIZARD_STEP.SETUP]: "organizations_setup",
  [ORG_WIZARD_STEP.VALIDATE]: "organizations_validate",
  [ORG_WIZARD_STEP.LAUNCH]: "organizations_launch",
} as const satisfies Record<OrgWizardStep, string>;

// What Lighthouse is told an organization is connected with.
const ORGANIZATIONS_CONNECTION_METHOD = "organizations";

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
    via,
  } = useProviderWizardStore();
  const connectDraft = useProviderWizardStore((state) => state.connectDraft);
  const {
    reset: resetOrgWizard,
    setOrganization,
    setOrganizationType,
    organizationType,
  } = useOrgSetupStore();

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
      setOrganizationType(orgInitialData.organizationType);
      setOrganization(
        orgInitialData.organizationId,
        orgInitialData.organizationName,
        orgInitialData.externalId,
      );
      setOrgCurrentStep(orgInitialData.targetStep);
      setOrgSetupPhase(orgInitialData.targetPhase);
      setFooterConfig(EMPTY_FOOTER_CONFIG);
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
      setCurrentStep(PROVIDER_WIZARD_STEP.CONNECT);
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
    orgInitialData,
    resetOrgWizard,
    resetProviderWizard,
    setMode,
    setOrganization,
    setOrganizationType,
    setProvider,
    setSecretId,
    setVia,
  ]);

  const isOrgDirectEntry = Boolean(orgInitialData);
  // Opened on an existing account's credentials, so the one-step AWS flow is not
  // in play. Same three fields the hydration above requires to start on CREDENTIALS.
  const isDirectCredentialsEntry = Boolean(
    initialProviderId && initialProviderType && initialProviderUid,
  );

  const isProviderFlow = wizardVariant === WIZARD_VARIANT.PROVIDER;
  const stepName = isProviderFlow
    ? PROVIDER_STEP_NAME[currentStep]
    : ORG_STEP_NAME[orgCurrentStep];

  const handleClose = () => {
    // Read providerId before reset clears it — non-null means a provider was connected.
    const connectedProviderId = useProviderWizardStore.getState().providerId;

    dispatchProviderFunnel({
      step: PROVIDER_FUNNEL_STEP.WIZARD_CLOSED,
      lastStep: stepName,
      providerCreated: connectedProviderId !== null,
    });

    resetProviderWizard();
    resetOrgWizard();
    setWizardVariant(WIZARD_VARIANT.PROVIDER);
    setCurrentStep(PROVIDER_WIZARD_STEP.CONNECT);
    setOrgCurrentStep(ORG_WIZARD_STEP.SETUP);
    setFooterConfig(EMPTY_FOOTER_CONFIG);
    setProviderTypeHint(null);
    setOrgSetupPhase(ORG_SETUP_PHASE.DETAILS);
    onOpenChange(false);

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
    if (
      useProviderWizardStore.getState().mode === PROVIDER_WIZARD_MODE.UPDATE
    ) {
      handleClose();
      return;
    }
    setCurrentStep(PROVIDER_WIZARD_STEP.LAUNCH);
  };

  const openOrganizationsFlow = (
    orgType: OrgFlowType = ORGANIZATION_TYPE.AWS,
  ) => {
    dispatchProviderFunnel({
      step: PROVIDER_FUNNEL_STEP.METHOD_SELECTED,
      providerType: orgType,
      method: PROVIDER_FUNNEL_METHOD.ORGANIZATION,
    });
    resetOrgWizard();
    setOrganizationType(orgType);
    setWizardVariant(WIZARD_VARIANT.ORGANIZATIONS);
    setOrgCurrentStep(ORG_WIZARD_STEP.SETUP);
    setFooterConfig(EMPTY_FOOTER_CONFIG);
    setProviderTypeHint(null);
    setOrgSetupPhase(ORG_SETUP_PHASE.DETAILS);
  };

  const backToProviderFlow = () => {
    // Organizations are entered from the connect step's tabs, so going back
    // lands on that provider's connect step instead of the provider picker.
    const cameFromProvider = organizationType;
    resetOrgWizard();
    setWizardVariant(WIZARD_VARIANT.PROVIDER);
    setCurrentStep(PROVIDER_WIZARD_STEP.CONNECT);
    setFooterConfig(EMPTY_FOOTER_CONFIG);
    setProviderTypeHint(cameFromProvider);
    setOrgSetupPhase(ORG_SETUP_PHASE.DETAILS);
  };

  const activeProviderType = providerTypeHint ?? providerType ?? null;
  // The method the connect step shows: picked in this wizard, else the one the
  // account was stored with, else the first listed. Only the method leaves the
  // draft; its values may hold secrets.
  const draftMethod =
    activeProviderType && connectDraft?.providerType === activeProviderType
      ? connectDraft.method
      : null;
  const providerMethod = activeProviderType
    ? resolveConnectMethod(activeProviderType, draftMethod ?? via).via
    : null;
  const connectionMethod = isProviderFlow
    ? providerMethod
    : ORGANIZATIONS_CONNECTION_METHOD;
  const docsLink = isProviderFlow
    ? getProviderHelpText(activeProviderType ?? "", currentStep, providerMethod)
        .link
    : ORG_DOCS_URL[organizationType];
  const resolvedFooterConfig: WizardFooterConfig = footerConfig;
  const modalTitle = getProviderWizardModalTitle(mode);

  return {
    connectionMethod,
    currentStep,
    docsLink,
    footerConfig,
    handleClose,
    handleDialogOpenChange,
    handleTestSuccess,
    isDirectCredentialsEntry,
    isOrgDirectEntry,
    isProviderFlow,
    mode,
    modalTitle,
    openOrganizationsFlow,
    organizationType,
    orgCurrentStep,
    orgSetupPhase,
    providerTypeHint,
    resolvedFooterConfig,
    setCurrentStep,
    setFooterConfig,
    setOrgCurrentStep,
    setOrgSetupPhase,
    setProviderTypeHint,
    stepName,
    backToProviderFlow,
    wizardVariant,
  };
}
