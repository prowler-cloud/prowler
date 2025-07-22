import { Control } from "react-hook-form";

import { CustomInput, CustomTextarea } from "@/components/ui/custom";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { GitHubCredentials } from "@/types";

export const GitHubAppForm = ({
  control,
}: {
  control: Control<GitHubCredentials>;
}) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md font-bold leading-9 text-default-foreground">
          GitHub App
        </div>
        <div className="text-sm text-default-500">
          Use GitHub App credentials for advanced integration. This requires
          both the App ID and Private Key.
        </div>
      </div>
      <CustomInput
        control={control}
        name={ProviderCredentialFields.GITHUB_APP_ID}
        label="GitHub App ID"
        labelPlacement="inside"
        placeholder="Enter the GitHub App ID"
        variant="bordered"
        isRequired={true}
        isInvalid={
          !!control._formState.errors[ProviderCredentialFields.GITHUB_APP_ID]
        }
      />
      <CustomTextarea
        control={control}
        name={ProviderCredentialFields.GITHUB_APP_KEY}
        label="GitHub App Private Key"
        labelPlacement="inside"
        placeholder="Paste your GitHub App Private Key content here"
        variant="bordered"
        minRows={8}
        isRequired={true}
        isInvalid={
          !!control._formState.errors[ProviderCredentialFields.GITHUB_APP_KEY]
        }
      />
    </>
  );
};
