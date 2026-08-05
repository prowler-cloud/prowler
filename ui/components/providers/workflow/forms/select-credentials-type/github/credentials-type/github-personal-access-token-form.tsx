"use client";

import { Control } from "react-hook-form";

import { WizardInputField } from "@/components/providers/workflow/forms/fields";
import { Button } from "@/components/shadcn";
import { PRECONFIGURED_CREDENTIAL_URLS } from "@/lib/external-urls";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";

export const GitHubPersonalAccessTokenForm = ({
  control,
}: {
  control: Control<any>;
}) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md text-text-neutral-primary leading-9 font-bold">
          Connect via Personal Access Token
        </div>
        <div className="text-text-neutral-tertiary text-sm">
          Please provide your GitHub personal access token.
        </div>
      </div>
      <WizardInputField
        control={control}
        name={ProviderCredentialFields.PERSONAL_ACCESS_TOKEN}
        type="password"
        label="Personal Access Token"
        labelPlacement="inside"
        placeholder="Enter your GitHub personal access token"
        variant="bordered"
        isRequired
      />
      <Button
        aria-label="Create a pre-configured Personal Access Token on GitHub"
        variant="link"
        className="h-auto w-fit min-w-0 p-0"
        asChild
      >
        <a
          href={PRECONFIGURED_CREDENTIAL_URLS.GITHUB_PERSONAL_ACCESS_TOKEN}
          target="_blank"
          rel="noopener noreferrer"
        >
          Create a pre-configured Personal Access Token on GitHub
        </a>
      </Button>
    </>
  );
};
