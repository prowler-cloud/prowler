import { useEffect, useState } from "react";
import { Control, UseFormSetValue, useWatch } from "react-hook-form";

import { CredentialsRoleHelper } from "@/components/providers/workflow";
import { WizardInputField } from "@/components/providers/workflow/forms/fields";
import { Badge } from "@/components/shadcn/badge/badge";
import { Checkbox } from "@/components/shadcn/checkbox/checkbox";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";
import { Separator } from "@/components/shadcn/separator/separator";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { AWSCredentialsRole } from "@/types";
import { IntegrationType } from "@/types/integrations";

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
  const isCloudEnv = process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true";
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
          <div className="text-md text-default-foreground leading-9 font-bold">
            Connect assuming IAM Role
          </div>
        )}
      </div>

      <span className="text-default-500 text-xs font-bold">
        Specify which AWS credentials to use
      </span>

      <div className="mb-4 flex flex-col gap-1.5">
        <Select
          value={credentialsType || defaultCredentialsType}
          onValueChange={(value) => {
            setValue(
              ProviderCredentialFields.CREDENTIALS_TYPE,
              value as "aws-sdk-default" | "access-secret-key",
            );
          }}
        >
          <SelectTrigger>
            <SelectValue placeholder="Select credentials type" />
          </SelectTrigger>
          <SelectContent className="z-[60]">
            <SelectItem value="aws-sdk-default">
              <div className="flex w-full items-center justify-between">
                <span>
                  {isCloudEnv
                    ? "Prowler Cloud will assume your IAM role"
                    : "AWS SDK Default"}
                </span>
                {isCloudEnv && (
                  <Badge variant="tag" className="ml-2">
                    Recommended
                  </Badge>
                )}
              </div>
            </SelectItem>
            <SelectItem value="access-secret-key">
              <div className="flex w-full items-center justify-between">
                <span>Access & Secret Key</span>
              </div>
            </SelectItem>
          </SelectContent>
        </Select>
      </div>

      {credentialsType === "access-secret-key" && (
        <>
          <WizardInputField
            control={control}
            name={ProviderCredentialFields.AWS_ACCESS_KEY_ID}
            type="password"
            label="AWS Access Key ID"
            labelPlacement="inside"
            placeholder="Enter the AWS Access Key ID"
            variant="bordered"
            isRequired
          />
          <WizardInputField
            control={control}
            name={ProviderCredentialFields.AWS_SECRET_ACCESS_KEY}
            type="password"
            label="AWS Secret Access Key"
            labelPlacement="inside"
            placeholder="Enter the AWS Secret Access Key"
            variant="bordered"
            isRequired
          />
          <WizardInputField
            control={control}
            name={ProviderCredentialFields.AWS_SESSION_TOKEN}
            type="password"
            label="AWS Session Token (optional)"
            labelPlacement="inside"
            placeholder="Enter the AWS Session Token"
            variant="bordered"
            isRequired={false}
          />
        </>
      )}
      <Separator />

      {type === "providers" ? (
        <span className="text-default-500 text-xs font-bold">Assume Role</span>
      ) : (
        <div className="flex items-center justify-between">
          <span className="text-default-500 text-xs font-bold">
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

          <span className="text-default-500 text-xs">Optional fields</span>
          <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-2">
            <WizardInputField
              control={control}
              name={ProviderCredentialFields.ROLE_SESSION_NAME}
              type="text"
              label="Role session name"
              labelPlacement="inside"
              placeholder="Enter the role session name"
              variant="bordered"
              isRequired={false}
            />
            <WizardInputField
              control={control}
              name={ProviderCredentialFields.SESSION_DURATION}
              type="number"
              label="Session duration (seconds)"
              labelPlacement="inside"
              placeholder="Enter the session duration (default: 3600 seconds)"
              variant="bordered"
              isRequired={false}
            />
          </div>
        </>
      )}
    </>
  );
};
