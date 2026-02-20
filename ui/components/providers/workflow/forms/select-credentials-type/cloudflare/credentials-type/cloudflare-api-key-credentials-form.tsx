"use client";

import { Control } from "react-hook-form";

import { CustomInput } from "@/components/ui/custom";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { CloudflareApiKeyCredentials } from "@/types";

export const CloudflareApiKeyCredentialsForm = ({
  control,
}: {
  control: Control<CloudflareApiKeyCredentials>;
}) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md text-default-foreground leading-9 font-bold">
          Connect via API Key + Email
        </div>
        <div className="text-default-500 text-sm">
          Provide your Cloudflare Global API Key and the email address
          associated with your Cloudflare account.
        </div>
      </div>
      <CustomInput
        control={control}
        name={ProviderCredentialFields.CLOUDFLARE_API_EMAIL}
        type="text"
        label="Email"
        labelPlacement="inside"
        placeholder="Enter your Cloudflare account email"
        variant="bordered"
        isRequired
      />
      <CustomInput
        control={control}
        name={ProviderCredentialFields.CLOUDFLARE_API_KEY}
        type="password"
        label="Global API Key"
        labelPlacement="inside"
        placeholder="Enter your Cloudflare Global API Key"
        variant="bordered"
        isRequired
      />
      <div className="text-default-400 text-xs">
        Credentials never leave your browser unencrypted and are stored as
        secrets in the backend. You can regenerate your API Key from the
        Cloudflare dashboard anytime if needed.
      </div>
    </>
  );
};
