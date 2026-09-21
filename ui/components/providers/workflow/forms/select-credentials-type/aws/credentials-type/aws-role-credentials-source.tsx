import { Control, UseFormSetValue } from "react-hook-form";

import { WizardInputField } from "@/components/providers/workflow/forms/fields";
import { Badge } from "@/components/shadcn/badge/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { AWSCredentialsRole } from "@/types";

interface AwsRoleCredentialsSourceProps {
  control: Control<AWSCredentialsRole>;
  setValue: UseFormSetValue<AWSCredentialsRole>;
  credentialsType: string;
  isCloudEnv: boolean;
}

/** Which credentials Prowler uses to assume the role, plus the keys when they are static. */
export const AwsRoleCredentialsSource = ({
  control,
  setValue,
  credentialsType,
  isCloudEnv,
}: AwsRoleCredentialsSourceProps) => (
  <>
    <span className="text-text-neutral-tertiary text-xs font-bold">
      Specify which AWS credentials to use
    </span>

    <div className="mb-4 flex flex-col gap-1.5">
      <Select
        value={credentialsType}
        onValueChange={(value) => {
          setValue(
            ProviderCredentialFields.CREDENTIALS_TYPE,
            value as "aws-sdk-default" | "access-secret-key",
          );
        }}
      >
        <SelectTrigger>
          <SelectValue placeholder="Select credentials type" />
        </SelectTrigger>
        <SelectContent className="z-[60]">
          <SelectItem value="aws-sdk-default">
            <div className="flex w-full items-center justify-between">
              <span>
                {isCloudEnv
                  ? "Prowler Cloud will assume your IAM role"
                  : "AWS SDK Default"}
              </span>
              {isCloudEnv && (
                <Badge variant="tag" className="ml-2">
                  Recommended
                </Badge>
              )}
            </div>
          </SelectItem>
          <SelectItem value="access-secret-key">
            <div className="flex w-full items-center justify-between">
              <span>Access & Secret Key</span>
            </div>
          </SelectItem>
        </SelectContent>
      </Select>
    </div>

    {credentialsType === "access-secret-key" && (
      <>
        <WizardInputField
          control={control}
          name={ProviderCredentialFields.AWS_ACCESS_KEY_ID}
          type="password"
          label="AWS Access Key ID"
          labelPlacement="inside"
          placeholder="Enter the AWS Access Key ID"
          variant="bordered"
          isRequired
        />
        <WizardInputField
          control={control}
          name={ProviderCredentialFields.AWS_SECRET_ACCESS_KEY}
          type="password"
          label="AWS Secret Access Key"
          labelPlacement="inside"
          placeholder="Enter the AWS Secret Access Key"
          variant="bordered"
          isRequired
        />
        <WizardInputField
          control={control}
          name={ProviderCredentialFields.AWS_SESSION_TOKEN}
          type="password"
          label="AWS Session Token (optional)"
          labelPlacement="inside"
          placeholder="Enter the AWS Session Token"
          variant="bordered"
          isRequired={false}
        />
      </>
    )}
  </>
);
