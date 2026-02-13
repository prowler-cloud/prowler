"use client";

import { Control } from "react-hook-form";

import { CustomInput } from "@/components/ui/custom";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";

export const GitHubPersonalAccessTokenForm = ({
  control,
}: {
  control: Control<any>;
}) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md text-default-foreground leading-9 font-bold">
          Connect via Personal Access Token
        </div>
        <div className="text-default-500 text-sm">
          Please provide your GitHub personal access token.
        </div>
      </div>
      <CustomInput
        control={control}
        name={ProviderCredentialFields.PERSONAL_ACCESS_TOKEN}
        type="password"
        label="Personal Access Token"
        labelPlacement="inside"
        placeholder="Enter your GitHub personal access token"
        variant="bordered"
        isRequired
      />
    </>
  );
};
