"use client";

import { IdIcon } from "@/components/icons";
import { CustomButton } from "@/components/ui/custom";
import { SnippetChip } from "@/components/ui/entities";
import { IntegrationType } from "@/types/integrations";

interface CredentialsRoleHelperProps {
  externalId: string;
  templateLinks: {
    cloudformation: string;
    cloudformationQuickLink: string;
    terraform: string;
  };
  integrationType?: IntegrationType;
}

export const CredentialsRoleHelper = ({
  externalId,
  templateLinks,
  integrationType,
}: CredentialsRoleHelperProps) => {
  const isAmazonS3 = integrationType === "amazon_s3";

  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-col gap-4">
        <p className="text-sm text-gray-600 dark:text-gray-400">
          A <strong>read-only IAM role</strong> must be manually created
          {isAmazonS3 ? " or updated" : ""}
        </p>

        <CustomButton
          ariaLabel="Use the following AWS CloudFormation Quick Link to deploy the IAM Role"
          color="transparent"
          className="h-auto w-fit min-w-0 p-0 text-blue-500"
          asLink={templateLinks.cloudformationQuickLink}
          target="_blank"
        >
          Use the following AWS CloudFormation Quick Link to create the IAM Role
        </CustomButton>

        <div className="flex items-center gap-2">
          <div className="h-px flex-1 bg-gray-200 dark:bg-gray-700" />
          <span className="text-xs font-bold text-gray-900 dark:text-gray-300">
            or
          </span>
          <div className="h-px flex-1 bg-gray-200 dark:bg-gray-700" />
        </div>

        <p className="text-sm text-gray-600 dark:text-gray-400">
          {isAmazonS3
            ? "Refer to the documentation"
            : "Use one of the following templates to create the IAM role"}
        </p>

        <div className="flex w-fit flex-col gap-2">
          <CustomButton
            ariaLabel="CloudFormation Template"
            color="transparent"
            className="h-auto w-fit min-w-0 p-0 text-blue-500"
            asLink={templateLinks.cloudformation}
            target="_blank"
          >
            CloudFormation {integrationType ? "" : "Template"}
          </CustomButton>
          <CustomButton
            ariaLabel="Terraform Code"
            color="transparent"
            className="h-auto w-fit min-w-0 p-0 text-blue-500"
            asLink={templateLinks.terraform}
            target="_blank"
          >
            Terraform {integrationType ? "" : "Code"}
          </CustomButton>
        </div>

        <div className="flex items-center gap-2">
          <span className="block text-xs font-medium text-default-500">
            External ID:
          </span>
          <SnippetChip value={externalId} icon={<IdIcon size={16} />} />
        </div>
      </div>
    </div>
  );
};
