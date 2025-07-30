"use client";

import { Control } from "react-hook-form";

import { CustomInput } from "@/components/ui/custom";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";

export const GitHubOAuthAppForm = ({ control }: { control: Control<any> }) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md font-bold leading-9 text-default-foreground">
          Connect via OAuth App
        </div>
        <div className="text-sm text-default-500">
          Please provide your GitHub OAuth App token.
        </div>
      </div>
      <CustomInput
        control={control}
        name={ProviderCredentialFields.OAUTH_APP_TOKEN}
        type="password"
        label="OAuth App Token"
        labelPlacement="inside"
        placeholder="Enter your GitHub OAuth App token"
        variant="bordered"
        isRequired
        isInvalid={
          !!control._formState.errors[ProviderCredentialFields.OAUTH_APP_TOKEN]
        }
      />
    </>
  );
};
