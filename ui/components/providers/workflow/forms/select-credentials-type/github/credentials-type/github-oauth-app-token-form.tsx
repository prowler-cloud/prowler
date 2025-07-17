import { Control } from "react-hook-form";

import { CustomInput } from "@/components/ui/custom";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { GitHubCredentials } from "@/types";

export const GitHubOAuthAppTokenForm = ({
  control,
}: {
  control: Control<GitHubCredentials>;
}) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md font-bold leading-9 text-default-foreground">
          OAuth App Token
        </div>
        <div className="text-sm text-default-500">
          Use an OAuth app token for application-level authentication. This is
          suitable for applications that need broader access.
        </div>
      </div>
      <CustomInput
        control={control}
        name={ProviderCredentialFields.OAUTH_APP_TOKEN}
        type="password"
        label="OAuth App Token"
        labelPlacement="inside"
        placeholder="Enter the OAuth App Token"
        variant="bordered"
        isRequired={true}
        isInvalid={
          !!control._formState.errors[ProviderCredentialFields.OAUTH_APP_TOKEN]
        }
      />
    </>
  );
};
