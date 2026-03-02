"use client";

import { Loader2 } from "lucide-react";
import { useEffect, useState } from "react";

import { getProvider } from "@/actions/providers";
import { useProviderWizardStore } from "@/store/provider-wizard/store";
import { PROVIDER_WIZARD_MODE } from "@/types/provider-wizard";

import {
  TestConnectionForm,
  TestConnectionProviderData,
} from "../../workflow/forms/test-connection-form";
import {
  WIZARD_FOOTER_ACTION_TYPE,
  WizardFooterConfig,
} from "./footer-controls";

interface TestConnectionStepProps {
  onSuccess: () => void;
  onResetCredentials: () => void;
  onFooterChange: (config: WizardFooterConfig) => void;
}

export function TestConnectionStep({
  onSuccess,
  onResetCredentials,
  onFooterChange,
}: TestConnectionStepProps) {
  const { providerId, providerType, mode, setSecretId } =
    useProviderWizardStore();
  const [providerData, setProviderData] =
    useState<TestConnectionProviderData | null>(null);
  const [isLoadingProvider, setIsLoadingProvider] = useState(true);
  const [isFormLoading, setIsFormLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const formId = "provider-wizard-test-connection-form";

  useEffect(() => {
    let isMounted = true;

    async function loadProvider() {
      if (!providerId || !providerType) {
        setErrorMessage("Provider information is missing.");
        setIsLoadingProvider(false);
        return;
      }

      setIsLoadingProvider(true);
      setErrorMessage(null);

      const formData = new FormData();
      formData.append("id", providerId);

      const response = await getProvider(formData);

      if (!isMounted) {
        return;
      }

      if (response?.errors?.length) {
        setErrorMessage(
          response.errors[0]?.detail || "Failed to load provider.",
        );
        setSecretId(null);
        setProviderData(null);
        setIsLoadingProvider(false);
        return;
      }

      const resolvedSecretId =
        response?.data?.relationships?.secret?.data?.id ?? null;
      setSecretId(resolvedSecretId);
      setProviderData(response as TestConnectionProviderData);
      setIsLoadingProvider(false);
    }

    loadProvider();

    return () => {
      isMounted = false;
    };
  }, [providerId, providerType, setSecretId]);

  useEffect(() => {
    const canSubmit = !isLoadingProvider && !errorMessage && !!providerData;

    onFooterChange({
      showBack: true,
      backLabel: "Back",
      backDisabled: isFormLoading,
      onBack: onResetCredentials,
      showAction: canSubmit,
      actionLabel: isFormLoading
        ? "Checking connection..."
        : "Check connection",
      actionDisabled: isFormLoading,
      actionType: WIZARD_FOOTER_ACTION_TYPE.SUBMIT,
      actionFormId: formId,
    });
  }, [
    errorMessage,
    isFormLoading,
    isLoadingProvider,
    mode,
    onFooterChange,
    onResetCredentials,
    providerData,
  ]);

  if (isLoadingProvider) {
    return (
      <div className="flex min-h-[320px] items-center justify-center">
        <Loader2 className="text-muted-foreground size-6 animate-spin" />
      </div>
    );
  }

  if (errorMessage || !providerData || !providerId || !providerType) {
    return (
      <div className="flex min-h-[320px] flex-col items-center justify-center gap-4 text-center">
        <p className="text-muted-foreground text-sm">
          {errorMessage || "Unable to load provider details."}
        </p>
      </div>
    );
  }

  return (
    <TestConnectionForm
      formId={formId}
      hideActions
      onLoadingChange={setIsFormLoading}
      searchParams={{
        type: providerType,
        id: providerId,
        updated: mode === PROVIDER_WIZARD_MODE.UPDATE ? "true" : "false",
      }}
      providerData={providerData}
      onSuccess={onSuccess}
      onResetCredentials={onResetCredentials}
    />
  );
}
