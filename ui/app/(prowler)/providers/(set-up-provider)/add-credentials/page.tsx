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
import { getProviderFormType } from "@/lib/provider-helpers";
import { ProviderType } from "@/types/providers";

interface Props {
  searchParams: { type: ProviderType; id: string; via?: string };
}

export default function AddCredentialsPage({ searchParams }: Props) {
  const { type: providerType, via } = searchParams;
  const formType = getProviderFormType(providerType, via);

  switch (formType) {
    case "selector":
      if (providerType === "aws") return <SelectViaAWS initialVia={via} />;
      if (providerType === "gcp") return <SelectViaGCP initialVia={via} />;
      if (providerType === "github") return <SelectViaGitHub initialVia={via} />;
      return null;
    
    case "credentials":
      return <AddViaCredentialsForm searchParams={searchParams} />;
    
    case "role":
      return <AddViaRoleForm searchParams={searchParams} />;
    
    case "service-account":
      return <AddViaServiceAccountForm searchParams={searchParams} />;
    
    default:
      return null;
  }
}
