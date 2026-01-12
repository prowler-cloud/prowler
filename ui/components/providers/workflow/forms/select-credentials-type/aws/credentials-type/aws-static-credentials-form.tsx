import { Control } from "react-hook-form";

import { CustomInput } from "@/components/ui/custom";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { AWSCredentials } from "@/types";

export const AWSStaticCredentialsForm = ({
  control,
}: {
  control: Control<AWSCredentials>;
}) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md text-default-foreground leading-9 font-bold">
          Connect via Credentials
        </div>
        <div className="text-default-500 text-sm">
          Please provide the information for your AWS credentials.
        </div>
      </div>
      <CustomInput
        control={control}
        name={ProviderCredentialFields.AWS_ACCESS_KEY_ID}
        type="password"
        label="AWS Access Key ID"
        labelPlacement="inside"
        placeholder="Enter the AWS Access Key ID"
        variant="bordered"
        isRequired
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
      />
      <CustomInput
        control={control}
        name={ProviderCredentialFields.AWS_SESSION_TOKEN}
        type="password"
        label="AWS Session Token"
        labelPlacement="inside"
        placeholder="Enter the AWS Session Token"
        variant="bordered"
        isRequired={false}
      />
    </>
  );
};
