"use client";

import { addCredentialsProvider } from "@/actions/providers/providers";
import { ProviderType } from "@/types";

import { BaseCredentialsForm } from "../../base-credentials-form";

export const AddViaServiceAccountForm = ({
  searchParams,
  providerUid,
}: {
  searchParams: { type: ProviderType; id: string };
  providerUid?: string;
}) => {
  const providerType = searchParams.type;
  const providerId = searchParams.id;

  const handleAddCredentials = async (formData: FormData) => {
    return await addCredentialsProvider(formData);
  };

  const successNavigationUrl = `/providers/test-connection?type=${providerType}&id=${providerId}`;

  return (
    <BaseCredentialsForm
      providerType={providerType}
      providerId={providerId}
      providerUid={providerUid}
      onSubmit={handleAddCredentials}
      successNavigationUrl={successNavigationUrl}
      submitButtonText="Next"
    />
  );
};
