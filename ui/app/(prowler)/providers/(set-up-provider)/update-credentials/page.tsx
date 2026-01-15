import { redirect } from "next/navigation";
import React from "react";

import { getProvider } from "@/actions/providers/providers";
import { CredentialsUpdateInfo } from "@/components/providers";
import {
  UpdateViaCredentialsForm,
  UpdateViaRoleForm,
} from "@/components/providers/workflow/forms";
import { UpdateViaServiceAccountForm } from "@/components/providers/workflow/forms/update-via-service-account-key-form";
import { getProviderFormType } from "@/lib/provider-helpers";
import { ProviderType } from "@/types/providers";

interface Props {
  searchParams: Promise<{
    type: ProviderType;
    id: string;
    via?: string;
    secretId?: string;
  }>;
}

export default async function UpdateCredentialsPage({ searchParams }: Props) {
  const resolvedSearchParams = await searchParams;
  const { type: providerType, via, id: providerId } = resolvedSearchParams;

  if (!providerId) {
    redirect("/providers");
  }

  const formType = getProviderFormType(providerType, via);

  const formData = new FormData();
  formData.append("id", providerId);
  const providerResponse = await getProvider(formData);

  if (providerResponse?.errors) {
    redirect("/providers");
  }

  const providerUid = providerResponse?.data?.attributes?.uid;

  switch (formType) {
    case "selector":
      return (
        <CredentialsUpdateInfo providerType={providerType} initialVia={via} />
      );

    case "credentials":
      return (
        <UpdateViaCredentialsForm
          searchParams={resolvedSearchParams}
          providerUid={providerUid}
        />
      );

    case "role":
      return (
        <UpdateViaRoleForm
          searchParams={resolvedSearchParams}
          providerUid={providerUid}
        />
      );

    case "service-account":
      return (
        <UpdateViaServiceAccountForm
          searchParams={resolvedSearchParams}
          providerUid={providerUid}
        />
      );

    default:
      return null;
  }
}
