"use client";

import { InfoIcon } from "@/components/icons";
import { SelectViaAWS } from "@/components/providers/workflow/forms/select-credentials-type/aws";
import { SelectViaGCP } from "@/components/providers/workflow/forms/select-credentials-type/gcp";
import { ProviderType } from "@/types/providers";

interface UpdateCredentialsInfoProps {
  providerType: ProviderType;
  initialVia?: string;
}

export const CredentialsUpdateInfo = ({
  providerType,
  initialVia,
}: UpdateCredentialsInfoProps) => {
  const renderSelectComponent = () => {
    if (providerType === "aws") {
      return <SelectViaAWS initialVia={initialVia} />;
    }
    if (providerType === "gcp") {
      return <SelectViaGCP initialVia={initialVia} />;
    }
    return null;
  };

  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm text-default-700">
        To update provider credentials,{" "}
        <strong>
          the same type that was originally configured must be used.
        </strong>
      </p>
      <div className="flex items-center rounded-lg border border-system-warning bg-system-warning-medium p-4 text-sm dark:text-default-300">
        <InfoIcon className="mr-2 inline h-4 w-4 flex-shrink-0" />
        <p>
          If the provider was configured with static credentials, updates must
          also use static credentials. If it was configured with a role in AWS
          (or service account in GCP),{" "}
          <strong>updates must use the same type.</strong>
        </p>
      </div>
      <p className="text-sm font-bold text-default-700">
        To switch from one type to another, the provider must be deleted and set
        up again.
      </p>
      {renderSelectComponent()}
    </div>
  );
};
