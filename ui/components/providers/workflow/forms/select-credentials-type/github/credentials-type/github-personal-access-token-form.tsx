import { Control } from "react-hook-form";

import { CustomInput } from "@/components/ui/custom";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { GitHubCredentials } from "@/types";

export const GitHubPersonalAccessTokenForm = ({
  control,
}: {
  control: Control<GitHubCredentials>;
}) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md font-bold leading-9 text-default-foreground">
          Personal Access Token
        </div>
        <div className="text-sm text-default-500">
          Use a personal access token for individual user authentication. This
          is the simplest method for personal use.
        </div>
      </div>
      <CustomInput
        control={control}
        name={ProviderCredentialFields.PERSONAL_ACCESS_TOKEN}
        type="password"
        label="Personal Access Token"
        labelPlacement="inside"
        placeholder="Enter the Personal Access Token"
        variant="bordered"
        isRequired={true}
        isInvalid={
          !!control._formState.errors[
            ProviderCredentialFields.PERSONAL_ACCESS_TOKEN
          ]
        }
      />
    </>
  );
};
