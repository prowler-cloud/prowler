import { Control } from "react-hook-form";

import { CustomInput } from "@/components/ui/custom";
import { AWSCredentials } from "@/types";

export const AWScredentialsForm = ({
  control,
}: {
  control: Control<AWSCredentials>;
}) => {
  return (
    <>
      <div className="text-left">
        <div className="text-2xl font-bold leading-9 text-default-foreground">
          Connect via Credentials
        </div>
        <div className="py-2 text-default-500">
          Please provide the information for your AWS credentials.
        </div>
      </div>
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
        label="AWS Session Token"
        labelPlacement="inside"
        placeholder="Enter the AWS Session Token"
        variant="bordered"
        isRequired={false}
        isInvalid={!!control._formState.errors.aws_session_token}
      />
    </>
  );
};
