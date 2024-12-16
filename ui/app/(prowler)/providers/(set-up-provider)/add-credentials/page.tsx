import React from "react";

import {
  ViaCredentialsForm,
  ViaRoleForm,
} from "@/components/providers/workflow/forms";
import { SelectViaAWS } from "@/components/providers/workflow/forms/select-via-aws/select-via-aws";

interface Props {
  searchParams: { type: string; id: string; via?: string };
}

export default function AddCredentialsPage({ searchParams }: Props) {
  return (
    <>
      {searchParams.type === "aws" && !searchParams.via && (
        <SelectViaAWS initialVia={searchParams.via} />
      )}

      {((searchParams.type === "aws" && searchParams.via === "credentials") ||
        searchParams.type !== "aws") && (
        <ViaCredentialsForm searchParams={searchParams} />
      )}

      {searchParams.type === "aws" && searchParams.via === "role" && (
        <ViaRoleForm searchParams={searchParams} />
      )}
    </>
  );
}
