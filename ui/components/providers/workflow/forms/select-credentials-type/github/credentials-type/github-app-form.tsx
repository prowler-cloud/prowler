"use client";

import { Control } from "react-hook-form";

import { CustomInput, CustomTextarea } from "@/components/ui/custom";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";

export const GitHubAppForm = ({
  control,
}: {
  control: Control<any>;
}) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md font-bold leading-9 text-default-foreground">
          Connect via GitHub App
        </div>
        <div className="text-sm text-default-500">
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
        isInvalid={
          !!control._formState.errors[
            ProviderCredentialFields.GITHUB_APP_ID
          ]
        }
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
        isInvalid={
          !!control._formState.errors[
            ProviderCredentialFields.GITHUB_APP_KEY
          ]
        }
      />
    </>
  );
};