import { Control, Controller } from "react-hook-form";

import {
  WizardInputField,
  WizardTextareaField,
} from "@/components/providers/workflow/forms/fields";
import { Combobox } from "@/components/shadcn/combobox";
import { FormControl, FormField, FormMessage } from "@/components/shadcn/form";
import { OCI_REGION_GROUPS } from "@/lib/provider-credentials/oci-regions";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { OCICredentials } from "@/types";

export const OracleCloudCredentialsForm = ({
  control,
}: {
  control: Control<OCICredentials>;
}) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md text-text-neutral-primary leading-9 font-bold">
          Connect via API Key
        </div>
        <div className="text-text-neutral-tertiary text-sm">
          Please provide your Oracle Cloud Infrastructure API key credentials.
        </div>
      </div>
      {/* Hidden input for tenancy - auto-populated from provider UID */}
      <Controller
        control={control}
        name={ProviderCredentialFields.OCI_TENANCY}
        render={({ field }) => <input type="hidden" {...field} />}
      />
      <WizardInputField
        control={control}
        name={ProviderCredentialFields.OCI_USER}
        type="text"
        label="User OCID"
        labelPlacement="inside"
        placeholder="ocid1.user.oc1..aaaaaaa..."
        variant="bordered"
        isRequired
      />
      <WizardInputField
        control={control}
        name={ProviderCredentialFields.OCI_FINGERPRINT}
        type="text"
        label="Fingerprint"
        labelPlacement="inside"
        placeholder="Enter the API key fingerprint"
        variant="bordered"
        isRequired
      />
      <FormField
        control={control}
        name={ProviderCredentialFields.OCI_REGION}
        render={({ field }) => (
          <div className="flex flex-col gap-1.5">
            <span className="text-text-neutral-tertiary text-xs font-light tracking-tight">
              Home Region<span className="text-text-error-primary">*</span>
            </span>
            <FormControl>
              <Combobox
                aria-label="Home Region"
                value={field.value ?? ""}
                onValueChange={field.onChange}
                groups={OCI_REGION_GROUPS}
                placeholder="Select your tenancy home region"
                searchPlaceholder="Search region..."
                emptyMessage="No region found."
                contentClassName="z-[60] sm:w-(--radix-popover-trigger-width) sm:max-w-none"
              />
            </FormControl>
            <span className="text-text-neutral-tertiary text-xs">
              Shown in the OCI Console under Tenancy Details. Used only to
              validate the credentials: all subscribed regions are scanned.
            </span>
            <FormMessage className="text-text-error-primary max-w-full text-xs" />
          </div>
        )}
      />
      <WizardTextareaField
        control={control}
        name={ProviderCredentialFields.OCI_KEY_CONTENT}
        label="Private Key Content"
        labelPlacement="inside"
        placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;MIIEpAIBAAKCAQEA...&#10;-----END RSA PRIVATE KEY-----"
        variant="bordered"
        minRows={6}
        isRequired
      />
      <WizardInputField
        control={control}
        name={ProviderCredentialFields.OCI_PASS_PHRASE}
        type="password"
        label="Passphrase (Optional)"
        labelPlacement="inside"
        placeholder="Enter passphrase if key is encrypted"
        variant="bordered"
        isRequired={false}
      />
      <div className="text-text-neutral-tertiary text-xs">
        Paste the raw content of your OCI private key file (PEM format). The key
        will be automatically encoded for secure transmission.
      </div>
    </>
  );
};
