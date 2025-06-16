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
        <div className="text-md font-bold leading-9 text-default-foreground">
          Connect via Credentials
        </div>
        <div className="text-sm text-default-500">
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
        label="AWS Session Token"
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
  );
};
