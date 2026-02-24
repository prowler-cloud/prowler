"use client";

import { useEffect, useState } from "react";

import { getProviderFormType } from "@/lib/provider-helpers";
import { useProviderWizardStore } from "@/store/provider-wizard/store";
import { PROVIDER_WIZARD_MODE } from "@/types/provider-wizard";
import { ProviderType } from "@/types/providers";

import {
  AddViaCredentialsForm,
  AddViaRoleForm,
  UpdateViaCredentialsForm,
  UpdateViaRoleForm,
} from "../../workflow/forms";
import { SelectViaAlibabaCloud } from "../../workflow/forms/select-credentials-type/alibabacloud";
import { SelectViaAWS } from "../../workflow/forms/select-credentials-type/aws";
import { SelectViaCloudflare } from "../../workflow/forms/select-credentials-type/cloudflare";
import {
  AddViaServiceAccountForm,
  SelectViaGCP,
} from "../../workflow/forms/select-credentials-type/gcp";
import { SelectViaGitHub } from "../../workflow/forms/select-credentials-type/github";
import { SelectViaM365 } from "../../workflow/forms/select-credentials-type/m365";
import { UpdateViaServiceAccountForm } from "../../workflow/forms/update-via-service-account-key-form";
import {
  WIZARD_FOOTER_ACTION_TYPE,
  WizardFooterConfig,
} from "./footer-controls";

interface CredentialsStepProps {
  onNext: () => void;
  onBack: () => void;
  onFooterChange: (config: WizardFooterConfig) => void;
}

export function CredentialsStep({
  onNext,
  onBack,
  onFooterChange,
}: CredentialsStepProps) {
  const { providerId, providerType, providerUid, via, secretId, mode, setVia } =
    useProviderWizardStore();
  const [isFormLoading, setIsFormLoading] = useState(false);
  const [isFormValid, setIsFormValid] = useState(false);

  const formId = "provider-wizard-credentials-form";
  const hasProviderContext = Boolean(providerType && providerId);
  const formType =
    providerType && providerId
      ? getProviderFormType(providerType, via || undefined)
      : null;
  const shouldUseUpdateForms =
    mode === PROVIDER_WIZARD_MODE.UPDATE && Boolean(secretId);

  const handleBack = () => {
    if (via) {
      setVia(null);
      return;
    }
    onBack();
  };

  const handleViaChange = (value: string) => {
    setVia(value);
  };

  useEffect(() => {
    setIsFormValid(false);
  }, [formType, via]);

  useEffect(() => {
    if (!hasProviderContext) {
      onFooterChange({
        showBack: true,
        backLabel: "Back",
        onBack,
        showAction: false,
        actionLabel: "Authenticate",
        actionType: WIZARD_FOOTER_ACTION_TYPE.BUTTON,
      });
      return;
    }

    const isSelector = formType === "selector";

    onFooterChange({
      showBack: true,
      backLabel: "Back",
      backDisabled: isFormLoading,
      onBack: () => {
        if (via) {
          setVia(null);
          return;
        }
        onBack();
      },
      showAction: !isSelector,
      actionLabel: "Authenticate",
      actionDisabled: isFormLoading || !isFormValid,
      actionType: WIZARD_FOOTER_ACTION_TYPE.SUBMIT,
      actionFormId: formId,
    });
  }, [
    hasProviderContext,
    formType,
    formId,
    isFormLoading,
    isFormValid,
    onBack,
    onFooterChange,
    setVia,
    via,
  ]);

  if (!providerType || !providerId) {
    return (
      <div className="flex h-full items-center justify-center py-8">
        <p className="text-muted-foreground text-sm">
          Provider details are missing. Go back and select a provider.
        </p>
      </div>
    );
  }

  if (formType === "selector") {
    if (providerType === "aws") {
      return (
        <SelectViaAWS
          initialVia={via || undefined}
          onViaChange={handleViaChange}
        />
      );
    }
    if (providerType === "gcp") {
      return (
        <SelectViaGCP
          initialVia={via || undefined}
          onViaChange={handleViaChange}
        />
      );
    }
    if (providerType === "github") {
      return (
        <SelectViaGitHub
          initialVia={via || undefined}
          onViaChange={handleViaChange}
        />
      );
    }
    if (providerType === "m365") {
      return (
        <SelectViaM365
          initialVia={via || undefined}
          onViaChange={handleViaChange}
        />
      );
    }
    if (providerType === "alibabacloud") {
      return (
        <SelectViaAlibabaCloud
          initialVia={via || undefined}
          onViaChange={handleViaChange}
        />
      );
    }
    if (providerType === "cloudflare") {
      return (
        <SelectViaCloudflare
          initialVia={via || undefined}
          onViaChange={handleViaChange}
        />
      );
    }
    return null;
  }

  const commonFormProps = {
    via,
    onSuccess: onNext,
    onBack: handleBack,
    providerUid: providerUid || undefined,
    formId,
    hideActions: true,
    onLoadingChange: setIsFormLoading,
    onValidityChange: setIsFormValid,
    validationMode: "onChange" as const,
  };

  if (formType === "credentials") {
    if (shouldUseUpdateForms) {
      return (
        <UpdateViaCredentialsForm
          searchParams={{
            type: providerType,
            id: providerId,
            secretId: secretId || undefined,
          }}
          {...commonFormProps}
        />
      );
    }

    return (
      <AddViaCredentialsForm
        searchParams={{ type: providerType, id: providerId }}
        {...commonFormProps}
      />
    );
  }

  if (formType === "role") {
    if (shouldUseUpdateForms) {
      return (
        <UpdateViaRoleForm
          searchParams={{
            type: providerType,
            id: providerId,
            secretId: secretId || undefined,
          }}
          {...commonFormProps}
        />
      );
    }

    return (
      <AddViaRoleForm
        searchParams={{ type: providerType, id: providerId }}
        {...commonFormProps}
      />
    );
  }

  if (formType === "service-account") {
    if (shouldUseUpdateForms) {
      return (
        <UpdateViaServiceAccountForm
          searchParams={{
            type: providerType,
            id: providerId,
            secretId: secretId || undefined,
          }}
          {...commonFormProps}
        />
      );
    }

    return (
      <AddViaServiceAccountForm
        searchParams={{ type: providerType as ProviderType, id: providerId }}
        {...commonFormProps}
      />
    );
  }

  return (
    <div className="flex flex-col gap-4 py-6">
      <p className="text-muted-foreground text-sm">
        Select a credential type to continue.
      </p>
    </div>
  );
}
