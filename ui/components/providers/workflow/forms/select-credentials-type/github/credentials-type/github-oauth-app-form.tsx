"use client";

import { Control } from "react-hook-form";

import { CustomInput } from "@/components/ui/custom";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";

export const GitHubOAuthAppForm = ({ control }: { control: Control<any> }) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md text-default-foreground leading-9 font-bold">
          Connect via OAuth App
        </div>
        <div className="text-default-500 text-sm">
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
      />
    </>
  );
};
