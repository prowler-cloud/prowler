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
  searchParams: {
    type: ProviderType;
    id: string;
    via?: string;
    secretId?: string;
  };
}

export default function UpdateCredentialsPage({ searchParams }: Props) {
  const { type: providerType, via } = searchParams;
  const formType = getProviderFormType(providerType, via);

  switch (formType) {
    case "selector":
      return (
        <CredentialsUpdateInfo providerType={providerType} initialVia={via} />
      );

    case "credentials":
      return <UpdateViaCredentialsForm searchParams={searchParams} />;

    case "role":
      return <UpdateViaRoleForm searchParams={searchParams} />;

    case "service-account":
      return <UpdateViaServiceAccountForm searchParams={searchParams} />;

    default:
      return null;
  }
}
