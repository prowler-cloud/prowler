import { useEffect, useState } from "react";
import { Control, UseFormSetValue, useWatch } from "react-hook-form";

import { CredentialsRoleHelper } from "@/components/providers/workflow";
import { WizardInputField } from "@/components/providers/workflow/forms/fields";
import { Checkbox } from "@/components/shadcn/checkbox/checkbox";
import { Separator } from "@/components/shadcn/separator/separator";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { isCloud } from "@/lib/shared/env";
import { AWSCredentialsRole } from "@/types";
import { IntegrationType } from "@/types/integrations";

import { AwsRoleCredentialsSource } from "./aws-role-credentials-source";
import { AwsRoleOptionalFields } from "./aws-role-optional-fields";

export const AWSRoleCredentialsForm = ({
  control,
  setValue,
  externalId,
  templateLinks,
  type = "providers",
  integrationType,
}: {
  control: Control<AWSCredentialsRole>;
  setValue: UseFormSetValue<AWSCredentialsRole>;
  externalId: string;
  templateLinks: {
    cloudformation: string;
    cloudformationQuickLink: string;
    terraform: string;
  };
  type?: "providers" | "integrations";
  integrationType?: IntegrationType;
}) => {
  const isCloudEnv = isCloud();
  const defaultCredentialsType = isCloudEnv
    ? "aws-sdk-default"
    : "access-secret-key";

  const credentialsType = useWatch({
    control,
    name: ProviderCredentialFields.CREDENTIALS_TYPE,
    defaultValue: defaultCredentialsType,
  });

  const [showOptionalRole, setShowOptionalRole] = useState(false);

  const showRoleSection =
    type === "providers" ||
    (isCloudEnv && credentialsType === "aws-sdk-default") ||
    showOptionalRole;

  // Track role section visibility and ensure external_id is set
  useEffect(() => {
    // Set show_role_section for validation
    setValue("show_role_section" as any, showRoleSection);

    // When role section is shown, ensure external_id is set
    // This handles both initial mount and when the section becomes visible
    if (showRoleSection && externalId) {
      setValue(ProviderCredentialFields.EXTERNAL_ID, externalId, {
        shouldValidate: false,
        shouldDirty: false,
      });
    }
  }, [showRoleSection, setValue, externalId]);

  return (
    <>
      <div className="flex flex-col">
        {type === "providers" && (
          <div className="text-md text-text-neutral-primary leading-9 font-bold">
            Connect assuming IAM Role
          </div>
        )}
      </div>

      <AwsRoleCredentialsSource
        control={control}
        setValue={setValue}
        credentialsType={credentialsType || defaultCredentialsType}
        isCloudEnv={isCloudEnv}
      />
      <Separator />

      {type === "providers" ? (
        <span className="text-text-neutral-tertiary text-xs font-bold">
          Assume Role
        </span>
      ) : (
        <div className="flex items-center justify-between">
          <span className="text-text-neutral-tertiary text-xs font-bold">
            {isCloudEnv && credentialsType === "aws-sdk-default"
              ? "Adding a role is required"
              : "Optionally add a role"}
          </span>
          <Checkbox
            checked={showRoleSection}
            onCheckedChange={(checked) => setShowOptionalRole(Boolean(checked))}
            disabled={isCloudEnv && credentialsType === "aws-sdk-default"}
            aria-label="Optionally add a role"
          />
        </div>
      )}

      {showRoleSection && (
        <>
          <CredentialsRoleHelper
            externalId={externalId}
            templateLinks={templateLinks}
            integrationType={integrationType}
          />

          <Separator />

          <WizardInputField
            control={control}
            name={ProviderCredentialFields.ROLE_ARN}
            type="text"
            label="Role ARN"
            labelPlacement="inside"
            placeholder="Enter the Role ARN"
            variant="bordered"
            isRequired={showRoleSection}
          />
          <WizardInputField
            control={control}
            name={ProviderCredentialFields.EXTERNAL_ID}
            type="text"
            label="External ID"
            labelPlacement="inside"
            placeholder={externalId}
            variant="bordered"
            defaultValue={externalId}
            isDisabled
            isRequired
          />

          <AwsRoleOptionalFields control={control} />
        </>
      )}
    </>
  );
};
