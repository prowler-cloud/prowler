import { Control, Controller } from "react-hook-form";

import {
  WizardInputField,
  WizardTextareaField,
} from "@/components/providers/workflow/forms/fields";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { GoogleWorkspaceCredentials } from "@/types";

export const GoogleWorkspaceCredentialsForm = ({
  control,
}: {
  control: Control<GoogleWorkspaceCredentials>;
}) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md text-default-foreground leading-9 font-bold">
          Connect via Service Account
        </div>
        <div className="text-default-500 text-sm">
          Provide your Service Account JSON and the admin email to impersonate.
        </div>
      </div>
      {/* Hidden input for customer_id - auto-populated from provider UID */}
      <Controller
        control={control}
        name={ProviderCredentialFields.GOOGLEWORKSPACE_CUSTOMER_ID}
        render={({ field }) => <input type="hidden" {...field} />}
      />
      <WizardTextareaField
        control={control}
        name={ProviderCredentialFields.GOOGLEWORKSPACE_CREDENTIALS_CONTENT}
        label="Service Account JSON"
        labelPlacement="inside"
        placeholder="Paste your Service Account JSON here"
        variant="bordered"
        minRows={10}
        isRequired
      />
      <WizardInputField
        control={control}
        name={ProviderCredentialFields.GOOGLEWORKSPACE_DELEGATED_USER}
        type="email"
        label="Delegated User Email"
        labelPlacement="inside"
        placeholder="admin@example.com"
        variant="bordered"
        isRequired
      />
      <div className="text-default-400 text-xs">
        Credentials never leave your browser unencrypted and are stored as
        secrets in the backend. You can revoke the Service Account from the
        Google Cloud Console anytime if needed.
      </div>
    </>
  );
};
