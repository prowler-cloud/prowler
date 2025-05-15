"use client";

import { Snippet } from "@nextui-org/react";
import { useSession } from "next-auth/react";

import { CustomButton } from "@/components/ui/custom";
import { getAWSCredentialsTemplateLinks } from "@/lib";

export const CredentialsRoleHelper = () => {
  const { data: session } = useSession();

  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-col gap-4">
        <p className="text-sm text-gray-600 dark:text-gray-400">
          A <strong>new read-only IAM role</strong> must be manually created.
        </p>

        <CustomButton
          ariaLabel="Use the following AWS CloudFormation Quick Link to deploy the IAM Role"
          color="transparent"
          className="h-auto w-fit min-w-0 p-0 text-blue-500"
          asLink={`${getAWSCredentialsTemplateLinks().cloudformationQuickLink}${session?.tenantId}`}
          target="_blank"
        >
          Use the following AWS CloudFormation Quick Link to deploy the IAM Role
        </CustomButton>

        <div className="flex items-center gap-2">
          <div className="h-px flex-1 bg-gray-200 dark:bg-gray-700" />
          <span className="text-xs font-bold text-gray-900 dark:text-gray-300">
            or
          </span>
          <div className="h-px flex-1 bg-gray-200 dark:bg-gray-700" />
        </div>
        <p className="text-sm text-gray-600 dark:text-gray-400">
          Use one of the following templates to create the IAM role:
        </p>

        <div className="flex w-fit flex-col gap-2">
          <CustomButton
            ariaLabel="CloudFormation Template"
            color="transparent"
            className="h-auto w-fit min-w-0 p-0 text-blue-500"
            asLink={getAWSCredentialsTemplateLinks().cloudformation}
            target="_blank"
          >
            CloudFormation Template
          </CustomButton>
          <CustomButton
            ariaLabel="Terraform Code"
            color="transparent"
            className="h-auto w-fit min-w-0 p-0 text-blue-500"
            asLink={getAWSCredentialsTemplateLinks().terraform}
            target="_blank"
          >
            Terraform Code
          </CustomButton>
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
