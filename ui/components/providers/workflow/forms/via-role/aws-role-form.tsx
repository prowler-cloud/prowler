import { Control } from "react-hook-form";

import { CustomInput } from "@/components/ui/custom";
import { AWSCredentialsRole } from "@/types";

export const AWSCredentialsRoleForm = ({
  control,
}: {
  control: Control<AWSCredentialsRole>;
}) => {
  return (
    <>
      <div className="mb-4 text-left">
        <div className="text-2xl font-bold leading-9 text-default-foreground">
          Connect assuming IAM Role
        </div>
        <div className="py-2 text-default-500">
          Please provide the information for your AWS credentials.
        </div>
      </div>

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
      <span className="text-sm text-default-500">Optional fields</span>
      <CustomInput
        control={control}
        name="aws_access_key_id"
        type="password"
        label="AWS Access Key ID"
        labelPlacement="inside"
        placeholder="Enter the AWS Access Key ID"
        variant="bordered"
        isRequired={false}
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
        isRequired={false}
        isInvalid={!!control._formState.errors.aws_secret_access_key}
      />
      <CustomInput
        control={control}
        name="aws_session_token"
        type="password"
        label="AWS Session Token"
        labelPlacement="inside"
        placeholder="Enter the AWS Session Token"
        variant="bordered"
        isRequired={false}
        isInvalid={!!control._formState.errors.aws_session_token}
      />
      <CustomInput
        control={control}
        name="external_id"
        type="text"
        label="External ID"
        labelPlacement="inside"
        placeholder="Enter the External ID"
        variant="bordered"
        isRequired={false}
        isInvalid={!!control._formState.errors.external_id}
      />

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
