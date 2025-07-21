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
import { SelectViaM365 } from "@/components/providers/workflow/forms/select-credentials-type/m365/select-via-m365";
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

      {searchParams.type === "m365" && !searchParams.via && (
        <SelectViaM365 initialVia={searchParams.via} />
      )}

      {((searchParams.type === "aws" && searchParams.via === "credentials") ||
        (searchParams.type === "gcp" && searchParams.via === "credentials") ||
        (searchParams.type === "m365" && searchParams.via === "credentials") ||
        (searchParams.type === "m365" && searchParams.via === "service-principal-user") ||
        (searchParams.type !== "aws" && searchParams.type !== "gcp" && searchParams.type !== "m365")) && (
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
