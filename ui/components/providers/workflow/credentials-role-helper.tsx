"use client";

import { ChevronDownIcon, ExternalLink } from "lucide-react";

import { IdIcon } from "@/components/icons";
import { Button } from "@/components/shadcn/button/button";
import { CodeSnippet } from "@/components/shadcn/code-snippet/code-snippet";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/shadcn/collapsible";
import {
  dispatchProviderFunnel,
  PROVIDER_FUNNEL_STEP,
  ROLE_TEMPLATE_KIND,
  type RoleTemplateKind,
} from "@/lib/provider-funnel/provider-funnel-events";
import { isCloud } from "@/lib/shared/env";
import { IntegrationType } from "@/types/integrations";

interface CredentialsRoleTemplateLinks {
  cloudformation: string;
  cloudformationQuickLink: string;
  terraform: string;
}

interface CredentialsRoleHelperProps {
  externalId: string;
  templateLinks: CredentialsRoleTemplateLinks;
  integrationType?: IntegrationType;
}

const describeRole = (integrationType?: IntegrationType) => {
  if (integrationType === "amazon_s3") {
    return "A read-only IAM role must be manually created or updated. Open the AWS console to do it from the stack; the External ID comes filled in.";
  }
  if (integrationType) {
    return "A read-only IAM role must be manually created. Open the AWS console to create it from the stack; the External ID comes filled in.";
  }
  return isCloud()
    ? "Open the AWS console to create a read-only IAM role that Prowler Cloud can assume. The stack comes with your External ID filled in."
    : "Open the AWS console to create a read-only IAM role that Prowler can assume. Fill in the AWS account Prowler runs from; the External ID comes filled in.";
};

/** One button creates the IAM role; the raw templates stay tucked away. */
export const CredentialsRoleHelper = ({
  externalId,
  templateLinks,
  integrationType,
}: CredentialsRoleHelperProps) => {
  // Integrations reuse this helper; only the add-provider journey is signalled.
  const signalTemplateOpened = (template: RoleTemplateKind) => {
    if (integrationType) return;
    dispatchProviderFunnel({
      step: PROVIDER_FUNNEL_STEP.ROLE_TEMPLATE_OPENED,
      template,
    });
  };

  return (
    <div className="flex flex-col gap-4">
      <p className="text-text-neutral-secondary text-sm">
        {describeRole(integrationType)}
      </p>

      <Button size="lg" className="w-fit" asChild>
        <a
          href={templateLinks.cloudformationQuickLink}
          target="_blank"
          rel="noopener noreferrer"
          onClick={() =>
            signalTemplateOpened(ROLE_TEMPLATE_KIND.CLOUDFORMATION_QUICK_CREATE)
          }
        >
          Create the IAM role in AWS
          <ExternalLink />
        </a>
      </Button>

      <div className="flex items-center gap-2">
        <span className="text-text-neutral-tertiary block text-xs font-medium">
          External ID:
        </span>
        <CodeSnippet value={externalId} icon={<IdIcon size={16} />} />
      </div>

      <Collapsible className="flex flex-col gap-4">
        <CollapsibleTrigger asChild>
          <Button
            type="button"
            variant="link"
            size="link-sm"
            className="group h-auto w-fit gap-1 p-0"
          >
            Other ways to create the role
            <ChevronDownIcon className="size-4 transition-transform group-data-[state=open]:rotate-180" />
          </Button>
        </CollapsibleTrigger>
        <CollapsibleContent className="flex w-fit flex-col gap-2">
          {integrationType === "amazon_s3" && (
            <p className="text-text-neutral-secondary text-sm">
              Refer to the documentation
            </p>
          )}
          <Button variant="link" className="h-auto w-fit min-w-0 p-0" asChild>
            <a
              href={templateLinks.cloudformation}
              target="_blank"
              rel="noopener noreferrer"
              onClick={() =>
                signalTemplateOpened(ROLE_TEMPLATE_KIND.CLOUDFORMATION_TEMPLATE)
              }
            >
              CloudFormation {integrationType ? "" : "Template"}
            </a>
          </Button>
          <Button variant="link" className="h-auto w-fit min-w-0 p-0" asChild>
            <a
              href={templateLinks.terraform}
              target="_blank"
              rel="noopener noreferrer"
              onClick={() => signalTemplateOpened(ROLE_TEMPLATE_KIND.TERRAFORM)}
            >
              Terraform {integrationType ? "" : "Code"}
            </a>
          </Button>
        </CollapsibleContent>
      </Collapsible>
    </div>
  );
};
