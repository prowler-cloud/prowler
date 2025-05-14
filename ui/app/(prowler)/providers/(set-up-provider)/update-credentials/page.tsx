import React from "react";

import { InfoIcon } from "@/components/icons";
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
        <>
          <div className="flex flex-col gap-4">
            <p className="text-sm text-default-700">
              To update provider credentials,{" "}
              <strong>
                the same type that was originally configured must be used.
              </strong>
            </p>
            <div className="flex items-center rounded-lg border border-system-warning bg-system-warning-medium p-4 text-sm dark:text-default-300">
              <InfoIcon className="mr-2 inline h-4 w-4 flex-shrink-0" />
              <p>
                If the provider was configured with static credentials, updates
                must also use static credentials. If it was configured with a
                role, updates must use a role.
              </p>
            </div>
            <p className="text-sm text-default-700">
              To switch from static credentials to a role (or vice versa), the
              provider must be deleted and set up again.
            </p>
            <SelectViaAWS initialVia={searchParams.via} />
          </div>
        </>
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
