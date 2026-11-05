import { Control } from "react-hook-form";

import {
  WizardInputField,
  WizardTextareaField,
} from "@/components/providers/workflow/forms/fields";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { OktaCredentials } from "@/types";

export const OktaCredentialsForm = ({
  control,
}: {
  control: Control<OktaCredentials>;
}) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md text-text-neutral-primary leading-9 font-bold">
          Connect via OAuth 2.0 Private Key JWT
        </div>
        <div className="text-text-neutral-tertiary text-sm">
          Provide the Client ID and PEM-encoded private key of an Okta API
          Services app whose matching public key (JWK) is registered on the
          service app.
        </div>
      </div>
      <WizardInputField
        control={control}
        name={ProviderCredentialFields.OKTA_CLIENT_ID}
        type="text"
        label="Client ID"
        labelPlacement="inside"
        placeholder="e.g. 0oa123456789abcdef"
        variant="bordered"
        isRequired
      />
      <WizardTextareaField
        control={control}
        name={ProviderCredentialFields.OKTA_PRIVATE_KEY}
        label="Private Key"
        labelPlacement="inside"
        placeholder="Paste your Okta app private key here"
        variant="bordered"
        isRequired
      />
      <div className="text-text-neutral-tertiary text-xs">
        The private key is sent over TLS and stored as a secret in the backend.
        You can rotate or revoke the public key from the Okta admin console at
        any time.
      </div>
    </>
  );
};
