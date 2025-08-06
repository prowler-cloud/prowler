import { Chip, Divider, Select, SelectItem, Switch } from "@nextui-org/react";
import { useState } from "react";
import { Control, UseFormSetValue, useWatch } from "react-hook-form";

import { CredentialsRoleHelper } from "@/components/providers/workflow";
import { CustomInput } from "@/components/ui/custom";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { AWSCredentialsRole } from "@/types";

export const AWSRoleCredentialsForm = ({
  control,
  setValue,
  externalId,
  templateLinks,
  type = "providers",
}: {
  control: Control<AWSCredentialsRole>;
  setValue: UseFormSetValue<AWSCredentialsRole>;
  externalId: string;
  templateLinks: {
    cloudformation: string;
    cloudformationQuickLink: string;
    terraform: string;
  };
  type?: "providers" | "s3-integration";
}) => {
  const [showRoleSection, setShowRoleSection] = useState(type === "providers");
  const isCloudEnv = process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true";

  // Set default credentials type based on environment
  const defaultCredentialsType = isCloudEnv
    ? "aws-sdk-default"
    : "access-secret-key";

  const credentialsType = useWatch({
    control,
    name: ProviderCredentialFields.CREDENTIALS_TYPE,
    defaultValue: defaultCredentialsType,
  });

  return (
    <>
      <div className="flex flex-col">
        {type === "providers" && (
          <div className="text-md font-bold leading-9 text-default-foreground">
            Connect assuming IAM Role
          </div>
        )}
      </div>

      <span className="text-xs font-bold text-default-500">
        Specify which AWS credentials to use
      </span>

      <Select
        name={ProviderCredentialFields.CREDENTIALS_TYPE}
        label="Authentication Method"
        placeholder="Select credentials type"
        defaultSelectedKeys={[defaultCredentialsType]}
        className="mb-4"
        variant="bordered"
        onSelectionChange={(keys) =>
          setValue(
            ProviderCredentialFields.CREDENTIALS_TYPE,
            Array.from(keys)[0] as "aws-sdk-default" | "access-secret-key",
          )
        }
      >
        <SelectItem
          key="aws-sdk-default"
          textValue={
            isCloudEnv
              ? "Prowler Cloud will assume your IAM role"
              : "AWS SDK Default"
          }
        >
          <div className="flex w-full items-center justify-between">
            <span>
              {isCloudEnv
                ? "Prowler Cloud will assume your IAM role"
                : "AWS SDK Default"}
            </span>
            {isCloudEnv && (
              <Chip size="sm" variant="flat" color="success" className="ml-2">
                Recommended
              </Chip>
            )}
          </div>
        </SelectItem>
        <SelectItem key="access-secret-key" textValue="Access & Secret Key">
          <div className="flex w-full items-center justify-between">
            <span>Access & Secret Key</span>
          </div>
        </SelectItem>
      </Select>

      {credentialsType === "access-secret-key" && (
        <>
          <CustomInput
            control={control}
            name={ProviderCredentialFields.AWS_ACCESS_KEY_ID}
            type="password"
            label="AWS Access Key ID"
            labelPlacement="inside"
            placeholder="Enter the AWS Access Key ID"
            variant="bordered"
            isRequired
            isInvalid={
              !!control._formState.errors[
                ProviderCredentialFields.AWS_ACCESS_KEY_ID
              ]
            }
          />
          <CustomInput
            control={control}
            name={ProviderCredentialFields.AWS_SECRET_ACCESS_KEY}
            type="password"
            label="AWS Secret Access Key"
            labelPlacement="inside"
            placeholder="Enter the AWS Secret Access Key"
            variant="bordered"
            isRequired
            isInvalid={
              !!control._formState.errors[
                ProviderCredentialFields.AWS_SECRET_ACCESS_KEY
              ]
            }
          />
          <CustomInput
            control={control}
            name={ProviderCredentialFields.AWS_SESSION_TOKEN}
            type="password"
            label="AWS Session Token (optional)"
            labelPlacement="inside"
            placeholder="Enter the AWS Session Token"
            variant="bordered"
            isRequired={false}
            isInvalid={
              !!control._formState.errors[
                ProviderCredentialFields.AWS_SESSION_TOKEN
              ]
            }
          />
        </>
      )}
      <Divider className="" />

      {type === "providers" ? (
        <span className="text-xs font-bold text-default-500">Assume Role</span>
      ) : (
        <div className="flex items-center justify-between">
          <span className="text-xs font-bold text-default-500">
            Optionally add a role
          </span>
          <Switch
            size="sm"
            isSelected={showRoleSection}
            onValueChange={setShowRoleSection}
          />
        </div>
      )}

      {showRoleSection && (
        <>
          <CredentialsRoleHelper
            externalId={externalId}
            templateLinks={templateLinks}
            type={type}
          />

          <Divider />

          <CustomInput
            control={control}
            name={ProviderCredentialFields.ROLE_ARN}
            type="text"
            label="Role ARN"
            labelPlacement="inside"
            placeholder="Enter the Role ARN"
            variant="bordered"
            isRequired={type === "providers"}
            isInvalid={
              !!control._formState.errors[ProviderCredentialFields.ROLE_ARN]
            }
          />
          <CustomInput
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
            isInvalid={
              !!control._formState.errors[ProviderCredentialFields.EXTERNAL_ID]
            }
          />

          <span className="text-xs text-default-500">Optional fields</span>
          <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-2">
            <CustomInput
              control={control}
              name={ProviderCredentialFields.ROLE_SESSION_NAME}
              type="text"
              label="Role session name"
              labelPlacement="inside"
              placeholder="Enter the role session name"
              variant="bordered"
              isRequired={false}
              isInvalid={
                !!control._formState.errors[
                  ProviderCredentialFields.ROLE_SESSION_NAME
                ]
              }
            />
            <CustomInput
              control={control}
              name={ProviderCredentialFields.SESSION_DURATION}
              type="number"
              label="Session duration (seconds)"
              labelPlacement="inside"
              placeholder="Enter the session duration (default: 3600 seconds)"
              variant="bordered"
              isRequired={false}
              isInvalid={
                !!control._formState.errors[
                  ProviderCredentialFields.SESSION_DURATION
                ]
              }
            />
          </div>
        </>
      )}
    </>
  );
};
