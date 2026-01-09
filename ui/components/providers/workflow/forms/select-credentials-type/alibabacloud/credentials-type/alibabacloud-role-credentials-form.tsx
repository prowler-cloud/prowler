import { Divider } from "@heroui/divider";
import { Control } from "react-hook-form";

import { CustomInput } from "@/components/ui/custom";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { AlibabaCloudCredentialsRole } from "@/types";

export const AlibabaCloudRoleCredentialsForm = ({
  control,
}: {
  control: Control<AlibabaCloudCredentialsRole>;
}) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md text-default-foreground leading-9 font-bold">
          Connect assuming RAM Role
        </div>
        <div className="text-default-500 text-sm">
          Provide the RAM Role ARN to assume, along with the Access Keys of a
          RAM user that has permission to assume the role.
        </div>
      </div>

      <span className="text-default-500 text-xs font-bold">
        RAM Role to Assume
      </span>

      <CustomInput
        control={control}
        name={ProviderCredentialFields.ALIBABACLOUD_ROLE_ARN}
        type="text"
        label="Role ARN"
        labelPlacement="inside"
        placeholder="e.g. acs:ram::1234567890123456:role/ProwlerRole"
        variant="bordered"
        isRequired
      />

      <Divider />

      <span className="text-default-500 text-xs font-bold">
        Credentials for Role Assumption
      </span>

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

      <span className="text-default-500 text-xs">Optional fields</span>

      <CustomInput
        control={control}
        name={ProviderCredentialFields.ALIBABACLOUD_ROLE_SESSION_NAME}
        type="text"
        label="Role Session Name"
        labelPlacement="inside"
        placeholder="Enter the role session name (default: ProwlerSession)"
        variant="bordered"
        isRequired={false}
      />

      <div className="text-default-400 text-xs">
        Keys never leave your browser unencrypted and are stored as secrets in
        the backend. The role will be assumed using STS to obtain temporary
        credentials.
      </div>
    </>
  );
};
