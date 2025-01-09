import { Alert, cn } from "@nextui-org/react";
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
        <>
          <div className="flex flex-col gap-4">
            <p className="text-sm text-default-500">
              If the provider was set up with static credentials, updates must
              use static credentials. If it was set up with a role, updates must
              use a role.
            </p>

            <Alert
              color="warning"
              variant="faded"
              classNames={{
                base: cn([
                  "border-1 border-default-200 dark:border-default-100",
                  "gap-x-4",
                ]),
              }}
              description={
                <>
                  To update provider credentials,{" "}
                  <strong>
                    you must use the same type that was originally configured.
                  </strong>{" "}
                </>
              }
            />
            <p className="text-sm text-default-500">
              To switch from static credentials to a role (or vice versa), you
              need to delete the provider and set it up again.
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
