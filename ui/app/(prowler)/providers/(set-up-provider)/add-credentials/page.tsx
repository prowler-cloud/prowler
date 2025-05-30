import React from "react";

import {
  ViaCredentialsForm,
  ViaRoleForm,
} from "@/components/providers/workflow/forms";
import { SelectViaAWS } from "@/components/providers/workflow/forms/select-credentials-type/aws";
import {
  SelectViaGCP,
  ViaServiceAccountForm,
} from "@/components/providers/workflow/forms/select-credentials-type/gcp";
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

      {((searchParams.type === "aws" && searchParams.via === "credentials") ||
        (searchParams.type === "gcp" && searchParams.via === "credentials") ||
        (searchParams.type !== "aws" && searchParams.type !== "gcp")) && (
        <ViaCredentialsForm searchParams={searchParams} />
      )}

      {searchParams.type === "aws" && searchParams.via === "role" && (
        <ViaRoleForm searchParams={searchParams} />
      )}

      {searchParams.type === "gcp" &&
        searchParams.via === "service-account" && (
          <ViaServiceAccountForm searchParams={searchParams} />
        )}
    </>
  );
}
