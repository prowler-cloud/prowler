"use client";

import { SelectViaAWS } from "@/components/providers/workflow/forms/select-credentials-type/aws";
import { SelectViaGCP } from "@/components/providers/workflow/forms/select-credentials-type/gcp";
import { SelectViaM365 } from "@/components/providers/workflow/forms/select-credentials-type/m365/select-via-m365";
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
    if (providerType === "m365") {
      return <SelectViaM365 initialVia={initialVia} />;
    }
    return null;
  };

  return <div className="flex flex-col gap-4">{renderSelectComponent()}</div>;
};
