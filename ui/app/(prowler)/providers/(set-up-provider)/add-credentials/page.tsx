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
import { ProviderType } from "@/types/providers";

interface Props {
  searchParams: { type: ProviderType; id: string; via?: string };
}

// Helper function to determine if the credentials form should be shown
const shouldShowCredentialsForm = (
  type: ProviderType,
  via?: string,
): boolean => {
  const credentialsConfig = {
    aws: ["credentials"],
    gcp: ["credentials"],
    github: ["personal_access_token", "oauth_app_token", "github_app"],
  };

  // If the type is in the configuration, check if the 'via' method is allowed
  if (credentialsConfig[type as keyof typeof credentialsConfig]) {
    return credentialsConfig[type as keyof typeof credentialsConfig].includes(
      via || "",
    );
  }

  // For unspecified types, show the default form
  return !["aws", "gcp", "github"].includes(type);
};

export default function AddCredentialsPage({ searchParams }: Props) {
  const { type, via } = searchParams;

  return (
    <>
      {/* Selectors for authentication methods */}
      {type === "aws" && !via && <SelectViaAWS initialVia={via} />}

      {type === "gcp" && !via && <SelectViaGCP initialVia={via} />}

      {type === "github" && !via && <SelectViaGitHub initialVia={via} />}

      {/* Credentials form */}
      {shouldShowCredentialsForm(type, via) && (
        <AddViaCredentialsForm searchParams={searchParams} />
      )}

      {/* Specific forms */}
      {type === "aws" && via === "role" && (
        <AddViaRoleForm searchParams={searchParams} />
      )}

      {type === "gcp" && via === "service-account" && (
        <AddViaServiceAccountForm searchParams={searchParams} />
      )}
    </>
  );
}
