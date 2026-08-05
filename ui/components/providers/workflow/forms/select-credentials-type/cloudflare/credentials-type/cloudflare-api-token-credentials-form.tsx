"use client";

import { Control } from "react-hook-form";

import { WizardInputField } from "@/components/providers/workflow/forms/fields";
import { Button } from "@/components/shadcn";
import { PRECONFIGURED_CREDENTIAL_URLS } from "@/lib/external-urls";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { CloudflareTokenCredentials } from "@/types";

export const CloudflareApiTokenCredentialsForm = ({
  control,
}: {
  control: Control<CloudflareTokenCredentials>;
}) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md text-text-neutral-primary leading-9 font-bold">
          Connect via API Token
        </div>
        <div className="text-text-neutral-tertiary text-sm">
          Provide a Cloudflare API Token with read permissions to the resources
          you want Prowler to assess. This is the recommended authentication
          method.
        </div>
      </div>
      <WizardInputField
        control={control}
        name={ProviderCredentialFields.CLOUDFLARE_API_TOKEN}
        type="password"
        label="API Token"
        labelPlacement="inside"
        placeholder="Enter your Cloudflare API Token"
        variant="bordered"
        isRequired
      />
      <Button
        aria-label="Create a pre-configured API Token on Cloudflare"
        variant="link"
        className="h-auto w-fit min-w-0 p-0"
        asChild
      >
        <a
          href={PRECONFIGURED_CREDENTIAL_URLS.CLOUDFLARE_API_TOKEN}
          target="_blank"
          rel="noopener noreferrer"
        >
          Create a pre-configured API Token on Cloudflare
        </a>
      </Button>
      <div className="text-text-neutral-tertiary text-xs">
        Tokens never leave your browser unencrypted and are stored as secrets in
        the backend. You can revoke the token from the Cloudflare dashboard
        anytime if needed.
      </div>
    </>
  );
};
