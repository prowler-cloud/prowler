"use client";

import { Snippet } from "@nextui-org/react";
import Link from "next/link";
import { useSession } from "next-auth/react";

export const CredentialsRoleHelper = () => {
  const { data: session } = useSession();

  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-col gap-4">
        <p className="text-sm text-gray-600 dark:text-gray-400">
          A <strong>new read-only IAM role</strong> must be manually created.
          Use one of the following templates to create the IAM role:
        </p>
        <div className="flex w-fit flex-col gap-2">
          <Link
            href="https://github.com/prowler-cloud/prowler/blob/master/permissions/templates/cloudformation/prowler-scan-role.yml"
            target="_blank"
            className="text-sm font-medium text-blue-500 hover:underline"
          >
            CloudFormation Template
          </Link>
          <Link
            href="https://github.com/prowler-cloud/prowler/blob/master/permissions/templates/terraform/main.tf"
            target="_blank"
            className="text-sm font-medium text-blue-500 hover:underline"
          >
            Terraform Code
          </Link>
        </div>
        <p className="text-xs font-bold text-gray-600 dark:text-gray-400">
          The External ID will also be required:
        </p>
        <Snippet
          className="max-w-full bg-gray-50 py-1 dark:bg-slate-800"
          color="warning"
          hideSymbol
        >
          <p className="whitespace-pre-line text-xs font-bold">
            {session?.tenantId}
          </p>
        </Snippet>
      </div>
    </div>
  );
};
