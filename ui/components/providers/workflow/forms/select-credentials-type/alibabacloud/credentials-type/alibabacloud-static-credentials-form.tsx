import { Control } from "react-hook-form";

import { CustomInput } from "@/components/ui/custom";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { AlibabaCloudCredentials } from "@/types";

export const AlibabaCloudStaticCredentialsForm = ({
  control,
}: {
  control: Control<AlibabaCloudCredentials>;
}) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md text-default-foreground leading-9 font-bold">
          Connect via Access Keys
        </div>
        <div className="text-default-500 text-sm">
          Provide a RAM user Access Key ID and Access Key Secret with read
          access to the resources you want Prowler to assess.
        </div>
      </div>
      <CustomInput
        control={control}
        name={ProviderCredentialFields.ALIBABACLOUD_ACCESS_KEY_ID}
        type="text"
        label="Access Key ID"
        labelPlacement="inside"
        placeholder="e.g. LTAI5txxxxxxxxxx"
        variant="bordered"
        isRequired
      />
      <CustomInput
        control={control}
        name={ProviderCredentialFields.ALIBABACLOUD_ACCESS_KEY_SECRET}
        type="password"
        label="Access Key Secret"
        labelPlacement="inside"
        placeholder="Enter the access key secret"
        variant="bordered"
        isRequired
      />
      <div className="text-default-400 text-xs">
        Keys never leave your browser unencrypted and are stored as secrets in
        the backend. Rotate the key from Alibaba Cloud RAM console anytime if
        needed.
      </div>
    </>
  );
};
