"use client";

import { Control } from "react-hook-form";

import { CustomInput } from "@/components/ui/custom";
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
        <div className="text-md text-default-foreground leading-9 font-bold">
          Connect via API Token
        </div>
        <div className="text-default-500 text-sm">
          Provide a Cloudflare API Token with read permissions to the resources
          you want Prowler to assess. This is the recommended authentication
          method.
        </div>
      </div>
      <CustomInput
        control={control}
        name={ProviderCredentialFields.CLOUDFLARE_API_TOKEN}
        type="password"
        label="API Token"
        labelPlacement="inside"
        placeholder="Enter your Cloudflare API Token"
        variant="bordered"
        isRequired
      />
      <div className="text-default-400 text-xs">
        Tokens never leave your browser unencrypted and are stored as secrets in
        the backend. You can revoke the token from the Cloudflare dashboard
        anytime if needed.
      </div>
    </>
  );
};
