import { Control } from "react-hook-form";

import { WizardInputField } from "@/components/providers/workflow/forms/fields";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { VercelCredentials } from "@/types";

export const VercelCredentialsForm = ({
  control,
}: {
  control: Control<VercelCredentials>;
}) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md text-default-foreground leading-9 font-bold">
          Connect via API Token
        </div>
        <div className="text-default-500 text-sm">
          Provide a Vercel API Token with read permissions to the resources you
          want Prowler to assess.
        </div>
      </div>
      <WizardInputField
        control={control}
        name={ProviderCredentialFields.VERCEL_API_TOKEN}
        type="password"
        label="API Token"
        labelPlacement="inside"
        placeholder="Enter your Vercel API Token"
        variant="bordered"
        isRequired
      />
      <div className="text-default-400 text-xs">
        Tokens never leave your browser unencrypted and are stored as secrets in
        the backend. You can revoke the token from the Vercel dashboard anytime
        at vercel.com/account/tokens.
      </div>
    </>
  );
};
