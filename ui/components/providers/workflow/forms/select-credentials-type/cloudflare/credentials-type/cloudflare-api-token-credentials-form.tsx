"use client";

import { Control } from "react-hook-form";

import { WizardInputField } from "@/components/providers/workflow/forms/fields";
import { Button } from "@/components/shadcn";
import {
  buildCloudflareAccountOwnedApiTokenUrl,
  PRECONFIGURED_CREDENTIAL_URLS,
} from "@/lib/external-urls";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { CloudflareTokenCredentials } from "@/types";

interface CloudflareApiTokenCredentialsFormProps {
  control: Control<CloudflareTokenCredentials>;
  // Cloudflare Account ID captured in the previous wizard step. When present,
  // it flows into the account-owned token URL as the account path segment so
  // Cloudflare lands the user directly on the correct account's Create Custom
  // Token page. When absent, only the user-scoped link is shown to avoid
  // relying on Cloudflare's `:account` router placeholder, which can silently
  // fall through when the user is signed into more than one account.
  providerUid?: string;
}

export const CloudflareApiTokenCredentialsForm = ({
  control,
  providerUid,
}: CloudflareApiTokenCredentialsFormProps) => {
  const trimmedProviderUid = providerUid?.trim();

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
      <div className="flex flex-col items-start gap-1">
        <Button variant="link" size="link-sm" asChild>
          <a
            href={PRECONFIGURED_CREDENTIAL_URLS.CLOUDFLARE_API_TOKEN_USER}
            target="_blank"
            rel="noopener noreferrer"
          >
            Create a pre-configured User API Token
          </a>
        </Button>
        {trimmedProviderUid && (
          <Button variant="link" size="link-sm" asChild>
            <a
              href={buildCloudflareAccountOwnedApiTokenUrl(trimmedProviderUid)}
              target="_blank"
              rel="noopener noreferrer"
            >
              Create a pre-configured Account-Owned API Token
            </a>
          </Button>
        )}
      </div>
      <div className="text-text-neutral-tertiary text-xs">
        Tokens never leave your browser unencrypted and are stored as secrets in
        the backend. You can revoke the token from the Cloudflare dashboard
        anytime if needed.
      </div>
    </>
  );
};
