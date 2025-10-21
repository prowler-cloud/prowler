import React from "react";

import {
  AddViaCredentialsForm,
  AddViaRoleForm,
} from "@/components/providers/workflow/forms";
import { SelectViaAWS } from "@/components/providers/workflow/forms/select-credentials-type/aws";
import {
  AddViaServiceAccountForm,
  SelectViaGCP,
} from "@/components/providers/workflow/forms/select-credentials-type/gcp";
import { SelectViaGitHub } from "@/components/providers/workflow/forms/select-credentials-type/github";
import { SelectViaM365 } from "@/components/providers/workflow/forms/select-credentials-type/m365";
import { getProviderFormType } from "@/lib/provider-helpers";
import { ProviderType } from "@/types/providers";

interface Props {
  searchParams: Promise<{ type: ProviderType; id: string; via?: string }>;
}

export default async function AddCredentialsPage({ searchParams }: Props) {
  const resolvedSearchParams = await searchParams;
  const { type: providerType, via } = resolvedSearchParams;
  const formType = getProviderFormType(providerType, via);

  switch (formType) {
    case "selector":
      if (providerType === "aws") return <SelectViaAWS initialVia={via} />;
      if (providerType === "gcp") return <SelectViaGCP initialVia={via} />;
      if (providerType === "github")
        return <SelectViaGitHub initialVia={via} />;
      if (providerType === "m365") return <SelectViaM365 initialVia={via} />;
      return null;

    case "credentials":
      return <AddViaCredentialsForm searchParams={resolvedSearchParams} />;

    case "role":
      return <AddViaRoleForm searchParams={resolvedSearchParams} />;

    case "service-account":
      return <AddViaServiceAccountForm searchParams={resolvedSearchParams} />;

    default:
      return null;
  }
}
