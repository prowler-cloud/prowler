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

export default function UpdateCredentialsPage({ searchParams }: Props) {
  return (
    <>
      {(searchParams.type === "aws" ||
        searchParams.type === "gcp" ||
        searchParams.type === "github") &&
        !searchParams.via && (
          <CredentialsUpdateInfo
            providerType={searchParams.type}
            initialVia={searchParams.via}
          />
        )}

      {((searchParams.type === "aws" && searchParams.via === "credentials") ||
        (searchParams.type === "gcp" && searchParams.via === "credentials") ||
        (searchParams.type === "github" &&
          searchParams.via === "personal_access_token") ||
        (searchParams.type === "github" &&
          searchParams.via === "oauth_app_token") ||
        (searchParams.type === "github" && searchParams.via === "github_app") ||
        (searchParams.type !== "aws" &&
          searchParams.type !== "gcp" &&
          searchParams.type !== "github")) && (
        <UpdateViaCredentialsForm searchParams={searchParams} />
      )}

      {searchParams.type === "aws" && searchParams.via === "role" && (
        <UpdateViaRoleForm searchParams={searchParams} />
      )}

      {searchParams.type === "gcp" &&
        searchParams.via === "service-account" && (
          <UpdateViaServiceAccountForm searchParams={searchParams} />
        )}
    </>
  );
}
