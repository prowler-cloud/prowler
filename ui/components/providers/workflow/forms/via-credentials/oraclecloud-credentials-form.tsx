import { Control, Controller } from "react-hook-form";

import { CustomInput, CustomTextarea } from "@/components/ui/custom";
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
        <div className="text-md text-default-foreground leading-9 font-bold">
          Connect via API Key
        </div>
        <div className="text-default-500 text-sm">
          Please provide your Oracle Cloud Infrastructure API key credentials.
        </div>
      </div>
      {/* Hidden input for tenancy - auto-populated from provider UID */}
      <Controller
        control={control}
        name={ProviderCredentialFields.OCI_TENANCY}
        render={({ field }) => <input type="hidden" {...field} />}
      />
      <CustomInput
        control={control}
        name={ProviderCredentialFields.OCI_USER}
        type="text"
        label="User OCID"
        labelPlacement="inside"
        placeholder="ocid1.user.oc1..aaaaaaa..."
        variant="bordered"
        isRequired
      />
      <CustomInput
        control={control}
        name={ProviderCredentialFields.OCI_FINGERPRINT}
        type="text"
        label="Fingerprint"
        labelPlacement="inside"
        placeholder="Enter the API key fingerprint"
        variant="bordered"
        isRequired
      />
      <CustomInput
        control={control}
        name={ProviderCredentialFields.OCI_REGION}
        type="text"
        label="Region"
        labelPlacement="inside"
        placeholder="e.g. us-ashburn-1"
        variant="bordered"
        isRequired
      />
      <CustomTextarea
        control={control}
        name={ProviderCredentialFields.OCI_KEY_CONTENT}
        label="Private Key Content"
        labelPlacement="inside"
        placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;MIIEpAIBAAKCAQEA...&#10;-----END RSA PRIVATE KEY-----"
        variant="bordered"
        minRows={6}
        isRequired
      />
      <CustomInput
        control={control}
        name={ProviderCredentialFields.OCI_PASS_PHRASE}
        type="password"
        label="Passphrase (Optional)"
        labelPlacement="inside"
        placeholder="Enter passphrase if key is encrypted"
        variant="bordered"
        isRequired={false}
      />
      <div className="text-default-400 text-xs">
        Paste the raw content of your OCI private key file (PEM format). The key
        will be automatically encoded for secure transmission.
      </div>
    </>
  );
};
