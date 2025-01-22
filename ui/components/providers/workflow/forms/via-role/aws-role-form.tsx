import { Select, SelectItem, Spacer } from "@nextui-org/react";
import { Control, UseFormSetValue, useWatch } from "react-hook-form";

import { CustomInput } from "@/components/ui/custom";
import { AWSCredentialsRole } from "@/types";

import { CredentialsRoleHelper } from "../../credentials-role-helper";

export const AWSCredentialsRoleForm = ({
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
    name: "credentials_type" as const,
    defaultValue: "aws-sdk-default",
  });

  return (
    <>
      <div className="flex flex-col gap-2">
        <div className="text-2xl font-bold leading-9 text-default-foreground">
          Connect assuming IAM Role
        </div>
        <div className="text-small text-default-500">
          Please provide the information for your AWS credentials.
        </div>
      </div>

      <span className="text-xs font-bold text-default-500">Authentication</span>

      <Select
        name="credentials_type"
        label="Authentication Method"
        placeholder="Select credentials type"
        defaultSelectedKeys={["aws-sdk-default"]}
        className="mb-4"
        variant="bordered"
        onSelectionChange={(keys) =>
          setValue(
            "credentials_type",
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
            name="aws_access_key_id"
            type="password"
            label="AWS Access Key ID"
            labelPlacement="inside"
            placeholder="Enter the AWS Access Key ID"
            variant="bordered"
            isRequired
            isInvalid={!!control._formState.errors.aws_access_key_id}
          />
          <CustomInput
            control={control}
            name="aws_secret_access_key"
            type="password"
            label="AWS Secret Access Key"
            labelPlacement="inside"
            placeholder="Enter the AWS Secret Access Key"
            variant="bordered"
            isRequired
            isInvalid={!!control._formState.errors.aws_secret_access_key}
          />
          <CustomInput
            control={control}
            name="aws_session_token"
            type="password"
            label="AWS Session Token (optional)"
            labelPlacement="inside"
            placeholder="Enter the AWS Session Token"
            variant="bordered"
            isRequired={false}
            isInvalid={!!control._formState.errors.aws_session_token}
          />
        </>
      )}
      <CredentialsRoleHelper />

      <Spacer y={2} />
      <span className="text-xs font-bold text-default-500">Assume Role</span>

      <CustomInput
        control={control}
        name="role_arn"
        type="text"
        label="Role ARN"
        labelPlacement="inside"
        placeholder="Enter the Role ARN"
        variant="bordered"
        isRequired
        isInvalid={!!control._formState.errors.role_arn}
      />
      <CustomInput
        control={control}
        name="external_id"
        type="text"
        label="External ID"
        labelPlacement="inside"
        placeholder="Enter the External ID"
        variant="bordered"
        defaultValue={externalId}
        isRequired
        isInvalid={!!control._formState.errors.external_id}
      />

      <span className="text-xs text-default-500">Optional fields</span>
      <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-2">
        <CustomInput
          control={control}
          name="role_session_name"
          type="text"
          label="Role Session Name"
          labelPlacement="inside"
          placeholder="Enter the Role Session Name"
          variant="bordered"
          isRequired={false}
          isInvalid={!!control._formState.errors.role_session_name}
        />
        <CustomInput
          control={control}
          name="session_duration"
          type="number"
          label="Session Duration (seconds)"
          labelPlacement="inside"
          placeholder="Enter the session duration (default: 3600)"
          variant="bordered"
          isRequired={false}
          isInvalid={!!control._formState.errors.session_duration}
        />
      </div>
    </>
  );
};
