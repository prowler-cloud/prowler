import { Control } from "react-hook-form";

import { CustomInput, CustomTextarea } from "@/components/ui/custom";
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
      <CustomInput
        control={control}
        name="user"
        type="text"
        label="User OCID"
        labelPlacement="inside"
        placeholder="ocid1.user.oc1..aaaaaaa..."
        variant="bordered"
        isRequired
        isInvalid={!!control._formState.errors.user}
      />
      <CustomInput
        control={control}
        name="fingerprint"
        type="text"
        label="Fingerprint"
        labelPlacement="inside"
        placeholder="Enter the API key fingerprint"
        variant="bordered"
        isRequired
        isInvalid={!!control._formState.errors.fingerprint}
      />
      <CustomInput
        control={control}
        name="region"
        type="text"
        label="Region"
        labelPlacement="inside"
        placeholder="e.g. us-ashburn-1"
        variant="bordered"
        isRequired
        isInvalid={!!control._formState.errors.region}
      />
      <CustomTextarea
        control={control}
        name="key_content"
        label="Private Key Content"
        labelPlacement="inside"
        placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;MIIEpAIBAAKCAQEA...&#10;-----END RSA PRIVATE KEY-----"
        variant="bordered"
        minRows={6}
        isRequired
        isInvalid={!!control._formState.errors.key_content}
      />
      <CustomInput
        control={control}
        name="pass_phrase"
        type="password"
        label="Passphrase (Optional)"
        labelPlacement="inside"
        placeholder="Enter passphrase if key is encrypted"
        variant="bordered"
        isRequired={false}
        isInvalid={!!control._formState.errors.pass_phrase}
      />
      <div className="text-default-400 text-xs">
        Paste the raw content of your OCI private key file (PEM format). The key will be automatically encoded for secure transmission.
      </div>
    </>
  );
};
