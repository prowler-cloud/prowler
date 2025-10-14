import React from "react";

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
  const { type: providerType, via } = resolvedSearchParams;
  const formType = getProviderFormType(providerType, via);

  switch (formType) {
    case "selector":
      return (
        <CredentialsUpdateInfo providerType={providerType} initialVia={via} />
      );

    case "credentials":
      return <UpdateViaCredentialsForm searchParams={resolvedSearchParams} />;

    case "role":
      return <UpdateViaRoleForm searchParams={resolvedSearchParams} />;

    case "service-account":
      return (
        <UpdateViaServiceAccountForm searchParams={resolvedSearchParams} />
      );

    default:
      return null;
  }
}
