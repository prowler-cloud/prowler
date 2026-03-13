"use client";

import { addCredentialsProvider } from "@/actions/providers/providers";
import { ProviderType } from "@/types";

import { BaseCredentialsForm } from "../../base-credentials-form";

export const AddViaServiceAccountForm = ({
  searchParams,
  providerUid,
  via,
  onSuccess,
  onBack,
  formId,
  hideActions,
  onLoadingChange,
  onValidityChange,
}: {
  searchParams: { type: ProviderType; id: string };
  providerUid?: string;
  via?: string | null;
  onSuccess?: () => void;
  onBack?: () => void;
  formId?: string;
  hideActions?: boolean;
  onLoadingChange?: (isLoading: boolean) => void;
  onValidityChange?: (isValid: boolean) => void;
}) => {
  const providerType = searchParams.type;
  const providerId = searchParams.id;

  const handleAddCredentials = async (formData: FormData) => {
    return await addCredentialsProvider(formData);
  };

  const successNavigationUrl = "/providers";

  return (
    <BaseCredentialsForm
      providerType={providerType}
      providerId={providerId}
      providerUid={providerUid}
      onSubmit={handleAddCredentials}
      successNavigationUrl={successNavigationUrl}
      via={via}
      onSuccess={onSuccess}
      onBack={onBack}
      formId={formId}
      hideActions={hideActions}
      onLoadingChange={onLoadingChange}
      onValidityChange={onValidityChange}
      submitButtonText="Next"
    />
  );
};
