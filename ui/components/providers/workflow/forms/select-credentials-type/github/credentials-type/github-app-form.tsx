"use client";

import { Control } from "react-hook-form";

import { CustomInput, CustomTextarea } from "@/components/ui/custom";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";

export const GitHubAppForm = ({ control }: { control: Control<any> }) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md text-default-foreground leading-9 font-bold">
          Connect via GitHub App
        </div>
        <div className="text-default-500 text-sm">
          Please provide your GitHub App ID and private key.
        </div>
      </div>
      <CustomInput
        control={control}
        name={ProviderCredentialFields.GITHUB_APP_ID}
        type="text"
        label="GitHub App ID"
        labelPlacement="inside"
        placeholder="Enter your GitHub App ID"
        variant="bordered"
        isRequired
      />
      <CustomTextarea
        control={control}
        name={ProviderCredentialFields.GITHUB_APP_KEY}
        label="GitHub App Private Key"
        labelPlacement="inside"
        placeholder="Paste your GitHub App private key here"
        variant="bordered"
        isRequired
        minRows={4}
      />
    </>
  );
};
