"use client";

import { UserPlus } from "lucide-react";
import { useState } from "react";

import { RadioCard } from "@/components/providers/radio-card";
import { ProviderTitleDocs } from "@/components/providers/workflow/provider-title-docs";
import { Badge } from "@/components/shadcn/badge/badge";
import { useAuth } from "@/hooks/use-auth";
import {
  dispatchProviderFunnel,
  PROVIDER_FUNNEL_METHOD,
  PROVIDER_FUNNEL_STEP,
} from "@/lib/provider-funnel/provider-funnel-events";
import { useProviderWizardStore } from "@/store/provider-wizard/store";
import { type OrgFlowType, toOrgFlowType } from "@/types/organizations";
import { CONNECT_PANEL, type ConnectPanel } from "@/types/provider-wizard";
import { getProviderDisplayName, isKnownProviderType } from "@/types/providers";

import {
  AwsKeysConnectForm,
  AwsRoleConnectForm,
} from "../aws/aws-connect-forms";
import { AWS_ACCESS_METHOD } from "../aws/types";
import { InviteTeammatePanel } from "../invite-teammate/invite-teammate-panel";

import {
  type ConnectMethod,
  getConnectMethods,
  getUidFieldDetails,
  resolveConnectMethod,
  UPDATE_SUBMIT_LABEL,
} from "./connect-methods";
import { GenericConnectForm } from "./generic-connect-form";
import {
  ONBOARDING_METHOD,
  OnboardingMethodTabs,
} from "./onboarding-method-tabs";
import { RegistryConnectForm } from "./registry-connect-form";
import type { ConnectFormProps, ConnectUiState } from "./types";

interface ProviderConnectStepProps {
  providerType: string;
  formId: string;
  /** The wizard was opened on an existing account: only its credentials change. */
  locked?: boolean;
  onConnected: () => void;
  onSelectOrganizations: (orgType: OrgFlowType) => void;
  onUiStateChange: (state: ConnectUiState) => void;
}

const readDraft = (providerType: string) => {
  const draft = useProviderWizardStore.getState().connectDraft;
  return draft?.providerType === providerType ? draft : null;
};

const initialMethod = (providerType: string, locked: boolean) => {
  const draft = readDraft(providerType);
  if (draft?.method !== undefined && draft.method !== null)
    return resolveConnectMethod(providerType, draft.method);
  // Updating an account starts on the method its secret was stored with.
  const storedVia = locked ? useProviderWizardStore.getState().via : null;
  return resolveConnectMethod(providerType, storedVia);
};

const initialPanel = (providerType: string): ConnectPanel =>
  readDraft(providerType)?.panel === CONNECT_PANEL.INVITE
    ? CONNECT_PANEL.INVITE
    : CONNECT_PANEL.ACCESS;

/** One step to register a provider account, store its credentials and test them. */
export function ProviderConnectStep({
  providerType,
  formId,
  locked = false,
  onConnected,
  onSelectOrganizations,
  onUiStateChange,
}: ProviderConnectStepProps) {
  const methods = getConnectMethods(providerType);
  // Local state needed: the access method only matters until the account is connected.
  const [method, setMethod] = useState<ConnectMethod>(() =>
    initialMethod(providerType, locked),
  );
  // Local state needed: whether the step shows the access forms or hands the
  // account over to a teammate. Separate from the method, which is the `via`
  // an account gets connected with.
  const [panel, setPanel] = useState<ConnectPanel>(() =>
    initialPanel(providerType),
  );
  // Local state needed: the active form reports it so the method cannot change mid-submit.
  const [isBusy, setIsBusy] = useState(false);
  const { permissions } = useAuth();
  // Inviting takes `manage_account`, which the API also asks of the roles list.
  const canInvite = permissions.manage_account === true;
  const orgType = locked ? undefined : toOrgFlowType(providerType);

  const isInvite = canInvite && panel === CONNECT_PANEL.INVITE;
  const showMethodCards = methods.length > 1 || canInvite;

  const chooseMethod = (next: ConnectMethod) => {
    setPanel(CONNECT_PANEL.ACCESS);
    setMethod(next);
    useProviderWizardStore.getState().setConnectDraft(providerType, {
      method: next.via,
      panel: CONNECT_PANEL.ACCESS,
    });
  };

  const chooseInvite = () => {
    if (isInvite) return;
    setPanel(CONNECT_PANEL.INVITE);
    useProviderWizardStore
      .getState()
      .setConnectDraft(providerType, { panel: CONNECT_PANEL.INVITE });
    dispatchProviderFunnel({
      step: PROVIDER_FUNNEL_STEP.METHOD_SELECTED,
      providerType,
      method: PROVIDER_FUNNEL_METHOD.INVITE_TEAMMATE,
    });
  };

  const formProps: ConnectFormProps = {
    formId,
    locked,
    submitLabel: locked
      ? UPDATE_SUBMIT_LABEL
      : getUidFieldDetails(providerType).submitLabel,
    onConnected,
    onBusyChange: setIsBusy,
    onUiStateChange,
  };

  return (
    <div className="flex flex-col gap-6">
      <ProviderTitleDocs providerType={providerType} />

      {orgType && (
        <OnboardingMethodTabs
          orgType={orgType}
          value={ONBOARDING_METHOD.SINGLE}
          onSelectOrganizations={() => onSelectOrganizations(orgType)}
        />
      )}

      {showMethodCards && (
        <div
          role="radiogroup"
          aria-label={`${getProviderDisplayName(providerType)} connection option`}
          className="flex flex-col gap-3"
        >
          <p className="text-text-neutral-secondary text-sm">
            {locked
              ? "Choose how Prowler should connect from now on."
              : "Choose how to connect it."}
          </p>
          <div className="grid gap-3 lg:grid-cols-2">
            {methods.map((option) => (
              <RadioCard
                key={option.via ?? "default"}
                icon={option.icon}
                title={option.label}
                selected={!isInvite && option.via === method.via}
                disabled={isBusy}
                onClick={() => chooseMethod(option)}
              >
                {option.recommended && (
                  <Badge variant="success" size="sm">
                    Recommended
                  </Badge>
                )}
              </RadioCard>
            ))}
            {canInvite && (
              <RadioCard
                icon={UserPlus}
                title="I don't have access, invite a teammate"
                selected={isInvite}
                disabled={isBusy}
                onClick={chooseInvite}
              />
            )}
          </div>
        </div>
      )}

      {isInvite ? (
        <InviteTeammatePanel
          providerType={providerType}
          formId={formId}
          onUiStateChange={onUiStateChange}
          onBusyChange={setIsBusy}
        />
      ) : (
        <ConnectForm
          key={method.via ?? "default"}
          providerType={providerType}
          method={method.via}
          {...formProps}
        />
      )}
    </div>
  );
}

interface ConnectFormSwitchProps extends ConnectFormProps {
  providerType: string;
  method: string | null;
}

function ConnectForm({
  providerType,
  method,
  ...props
}: ConnectFormSwitchProps) {
  if (providerType === "aws") {
    return method === AWS_ACCESS_METHOD.CREDENTIALS ? (
      <AwsKeysConnectForm {...props} />
    ) : (
      <AwsRoleConnectForm {...props} />
    );
  }
  if (isKnownProviderType(providerType)) {
    return (
      <GenericConnectForm
        providerType={providerType}
        method={method}
        {...props}
      />
    );
  }
  return <RegistryConnectForm providerType={providerType} {...props} />;
}
