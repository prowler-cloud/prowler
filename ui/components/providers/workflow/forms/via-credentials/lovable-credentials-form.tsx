import { Control } from "react-hook-form";

import { WizardInputField } from "@/components/providers/workflow/forms/fields";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { LovableCredentials } from "@/types";

export const LovableCredentialsForm = ({
  control,
}: {
  control: Control<LovableCredentials>;
}) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md text-default-foreground leading-9 font-bold">
          Connect via API Token
        </div>
        <div className="text-default-500 text-sm">
          Provide a Lovable Cloud API Token with read access to the workspace
          and projects you want Prowler to assess.
        </div>
      </div>
      <WizardInputField
        control={control}
        name={ProviderCredentialFields.LOVABLE_API_TOKEN}
        type="password"
        label="Lovable API Token"
        labelPlacement="inside"
        placeholder="Enter your Lovable Cloud API Token"
        variant="bordered"
        isRequired
      />

      <div className="flex flex-col">
        <div className="text-md text-default-foreground leading-9 font-bold">
          Optional: Supabase access token
        </div>
        <div className="text-default-500 text-sm">
          If your Lovable apps are backed by Supabase, supply a Supabase
          Management API token to enable deeper checks (RLS posture, Edge
          Function authentication, storage privacy).
        </div>
      </div>
      <WizardInputField
        control={control}
        name={ProviderCredentialFields.LOVABLE_SUPABASE_ACCESS_TOKEN}
        type="password"
        label="Supabase Access Token (optional)"
        labelPlacement="inside"
        placeholder="sbp_..."
        variant="bordered"
      />

      <div className="text-default-400 text-xs">
        Tokens never leave your browser unencrypted and are stored as secrets in
        the backend. You can revoke either token from the relevant dashboard at
        any time.
      </div>
    </>
  );
};
