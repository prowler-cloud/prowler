import React from "react";

import { CredentialsUpdateInfo } from "@/components/providers/credentials-update-info";
import {
  UpdateViaCredentialsForm,
  UpdateViaRoleForm,
} from "@/components/providers/workflow/forms";
import { UpdateViaServiceAccountForm } from "@/components/providers/workflow/forms/update-via-service-account-key-form";
import { ProviderType } from "@/types/providers";

interface Props {
  searchParams: {
    type: ProviderType;
    id: string;
    via?: string;
    secretId?: string;
  };
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

export default function UpdateCredentialsPage({ searchParams }: Props) {
  const { type, via } = searchParams;

  return (
    <>
      {/* Credentials update info for supported providers */}
      {(type === "aws" || type === "gcp" || type === "github") && !via && (
        <CredentialsUpdateInfo providerType={type} initialVia={via} />
      )}

      {/* Credentials form */}
      {shouldShowCredentialsForm(type, via) && (
        <UpdateViaCredentialsForm searchParams={searchParams} />
      )}

      {/* Specific forms */}
      {type === "aws" && via === "role" && (
        <UpdateViaRoleForm searchParams={searchParams} />
      )}

      {type === "gcp" && via === "service-account" && (
        <UpdateViaServiceAccountForm searchParams={searchParams} />
      )}
    </>
  );
}
