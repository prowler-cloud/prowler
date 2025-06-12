import { Divider, Select, SelectItem, Spacer } from "@nextui-org/react";
import { Control, UseFormSetValue, useWatch } from "react-hook-form";

import { CredentialsRoleHelper } from "@/components/providers/workflow";
import { CustomInput } from "@/components/ui/custom";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { AWSCredentialsRole } from "@/types";

export const AWSRoleCredentialsForm = ({
  control,
  setValue,
  externalId,
}: {
  control: Control<AWSCredentialsRole>;
  setValue: UseFormSetValue<AWSCredentialsRole>;
  externalId: string;
}) => {
  const credentialsType = useWatch({
    control,
    name: ProviderCredentialFields.CREDENTIALS_TYPE,
    defaultValue: "aws-sdk-default",
  });

  return (
    <>
      <div className="flex flex-col">
        <div className="text-md font-bold leading-9 text-default-foreground">
          Connect assuming IAM Role
        </div>
        <div className="text-sm text-default-500">
          Please provide the information for your AWS credentials.
        </div>
      </div>

      <span className="text-xs font-bold text-default-500">Authentication</span>

      <Select
        name={ProviderCredentialFields.CREDENTIALS_TYPE}
        label="Authentication Method"
        placeholder="Select credentials type"
        defaultSelectedKeys={["aws-sdk-default"]}
        className="mb-4"
        variant="bordered"
        onSelectionChange={(keys) =>
          setValue(
            ProviderCredentialFields.CREDENTIALS_TYPE,
            Array.from(keys)[0] as "aws-sdk-default" | "access-secret-key",
          )
        }
      >
        <SelectItem key="aws-sdk-default">AWS SDK default</SelectItem>
        <SelectItem key="access-secret-key">Access & secret key</SelectItem>
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
      <Divider />
      <span className="text-xs font-bold text-default-500">Assume Role</span>
      <CredentialsRoleHelper />

      <Spacer y={2} />

      <CustomInput
        control={control}
        name={ProviderCredentialFields.ROLE_ARN}
        type="text"
        label="Role ARN"
        labelPlacement="inside"
        placeholder="Enter the Role ARN"
        variant="bordered"
        isRequired
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
          label="Role Session Name"
          labelPlacement="inside"
          placeholder="Enter the Role Session Name"
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
          label="Session Duration (seconds)"
          labelPlacement="inside"
          placeholder="Enter the session duration (default: 3600)"
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
  );
};
