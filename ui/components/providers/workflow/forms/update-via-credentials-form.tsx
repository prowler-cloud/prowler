"use client";

import { updateCredentialsProvider } from "@/actions/providers/providers";
import { ProviderType } from "@/types";

import { BaseCredentialsForm } from "./base-credentials-form";

export const UpdateViaCredentialsForm = ({
  searchParams,
}: {
  searchParams: { type: string; id: string; secretId?: string };
}) => {
  const providerType = searchParams.type as ProviderType;
  const providerId = searchParams.id;
  const providerSecretId = searchParams.secretId || "";

  const handleUpdateCredentials = async (formData: FormData) => {
    return await updateCredentialsProvider(providerSecretId, formData);
  };

  const successNavigationUrl = `/providers/test-connection?type=${providerType}&id=${providerId}&updated=true`;

  return (
    <BaseCredentialsForm
      providerType={providerType}
      providerId={providerId}
      onSubmit={handleUpdateCredentials}
      successNavigationUrl={successNavigationUrl}
      submitButtonText="Next"
    />
  );
};
