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

export default function AddCredentialsPage({ searchParams }: Props) {
  return (
    <>
      {searchParams.type === "aws" && !searchParams.via && (
        <SelectViaAWS initialVia={searchParams.via} />
      )}

      {searchParams.type === "gcp" && !searchParams.via && (
        <SelectViaGCP initialVia={searchParams.via} />
      )}

      {searchParams.type === "github" && !searchParams.via && (
        <SelectViaGitHub initialVia={searchParams.via} />
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
        <AddViaCredentialsForm searchParams={searchParams} />
      )}

      {searchParams.type === "aws" && searchParams.via === "role" && (
        <AddViaRoleForm searchParams={searchParams} />
      )}

      {searchParams.type === "gcp" &&
        searchParams.via === "service-account" && (
          <AddViaServiceAccountForm searchParams={searchParams} />
        )}
    </>
  );
}
