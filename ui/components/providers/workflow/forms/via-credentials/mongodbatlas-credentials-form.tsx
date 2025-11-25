import { Control } from "react-hook-form";

import { CustomInput } from "@/components/ui/custom";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { MongoDBAtlasCredentials } from "@/types";

export const MongoDBAtlasCredentialsForm = ({
  control,
}: {
  control: Control<MongoDBAtlasCredentials>;
}) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md text-default-foreground leading-9 font-bold">
          Connect via API Keys
        </div>
        <div className="text-default-500 text-sm">
          Provide an organization-level MongoDB Atlas API public and private key
          with read access to the resources you want Prowler to assess.
        </div>
      </div>
      <CustomInput
        control={control}
        name={ProviderCredentialFields.ATLAS_PUBLIC_KEY}
        type="text"
        label="Atlas Public Key"
        labelPlacement="inside"
        placeholder="e.g. abcdefgh"
        variant="bordered"
        isRequired
      />
      <CustomInput
        control={control}
        name={ProviderCredentialFields.ATLAS_PRIVATE_KEY}
        type="password"
        label="Atlas Private Key"
        labelPlacement="inside"
        placeholder="Enter the private key"
        variant="bordered"
        isRequired
      />
      <div className="text-default-400 text-xs">
        Keys never leave your browser unencrypted and are stored as secrets in
        the backend. Rotate the key from MongoDB Atlas anytime if needed.
      </div>
    </>
  );
};
