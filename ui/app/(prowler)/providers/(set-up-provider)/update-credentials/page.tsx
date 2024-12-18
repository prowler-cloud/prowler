import React from "react";

import {
  UpdateViaCredentialsForm,
  UpdateViaRoleForm,
} from "@/components/providers/workflow/forms";
import { SelectViaAWS } from "@/components/providers/workflow/forms/select-via-aws/select-via-aws";

interface Props {
  searchParams: { type: string; id: string; via?: string };
}

export default function UpdateCredentialsPage({ searchParams }: Props) {
  return (
    <>
      {searchParams.type === "aws" && !searchParams.via && (
        <SelectViaAWS initialVia={searchParams.via} />
      )}

      {((searchParams.type === "aws" && searchParams.via === "credentials") ||
        searchParams.type !== "aws") && (
        <UpdateViaCredentialsForm searchParams={searchParams} />
      )}

      {searchParams.type === "aws" && searchParams.via === "role" && (
        <UpdateViaRoleForm searchParams={searchParams} />
      )}
    </>
  );
}
