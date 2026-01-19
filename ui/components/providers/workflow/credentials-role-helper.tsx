"use client";

import { IdIcon } from "@/components/icons";
import { Button } from "@/components/shadcn";
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

        <Button
          aria-label="Use the following AWS CloudFormation Quick Link to deploy the IAM Role"
          variant="link"
          className="h-auto w-fit min-w-0 p-0"
          asChild
        >
          <a
            href={templateLinks.cloudformationQuickLink}
            target="_blank"
            rel="noopener noreferrer"
          >
            Use the following AWS CloudFormation Quick Link to create the IAM
            Role
          </a>
        </Button>

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
          <Button
            aria-label="CloudFormation Template"
            variant="link"
            className="h-auto w-fit min-w-0 p-0"
            asChild
          >
            <a
              href={templateLinks.cloudformation}
              target="_blank"
              rel="noopener noreferrer"
            >
              CloudFormation {integrationType ? "" : "Template"}
            </a>
          </Button>
          <Button
            aria-label="Terraform Code"
            variant="link"
            className="h-auto w-fit min-w-0 p-0"
            asChild
          >
            <a
              href={templateLinks.terraform}
              target="_blank"
              rel="noopener noreferrer"
            >
              Terraform {integrationType ? "" : "Code"}
            </a>
          </Button>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-default-500 block text-xs font-medium">
            External ID:
          </span>
          <SnippetChip value={externalId} icon={<IdIcon size={16} />} />
        </div>
      </div>
    </div>
  );
};
