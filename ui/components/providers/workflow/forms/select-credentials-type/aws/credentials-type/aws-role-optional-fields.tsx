import { Control } from "react-hook-form";

import { WizardInputField } from "@/components/providers/workflow/forms/fields";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { AWSCredentialsRole } from "@/types";

interface AwsRoleOptionalFieldsProps {
  control: Control<AWSCredentialsRole>;
}

/** Session name and duration of the assumed role; both optional. */
export const AwsRoleOptionalFields = ({
  control,
}: AwsRoleOptionalFieldsProps) => (
  <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
    <WizardInputField
      control={control}
      name={ProviderCredentialFields.ROLE_SESSION_NAME}
      type="text"
      label="Role session name"
      labelPlacement="inside"
      placeholder="Enter the role session name"
      variant="bordered"
      isRequired={false}
    />
    <WizardInputField
      control={control}
      name={ProviderCredentialFields.SESSION_DURATION}
      type="number"
      label="Session duration (seconds)"
      labelPlacement="inside"
      placeholder="Enter the session duration (default: 3600 seconds)"
      variant="bordered"
      isRequired={false}
    />
  </div>
);
