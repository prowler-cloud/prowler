"use client";

import { SelectViaAlibabaCloud } from "@/components/providers/workflow/forms/select-credentials-type/alibabacloud";
import { SelectViaAWS } from "@/components/providers/workflow/forms/select-credentials-type/aws";
import { SelectViaCloudflare } from "@/components/providers/workflow/forms/select-credentials-type/cloudflare";
import { SelectViaGCP } from "@/components/providers/workflow/forms/select-credentials-type/gcp";
import { SelectViaGitHub } from "@/components/providers/workflow/forms/select-credentials-type/github";
import { SelectViaM365 } from "@/components/providers/workflow/forms/select-credentials-type/m365";
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
    if (providerType === "github") {
      return <SelectViaGitHub initialVia={initialVia} />;
    }
    if (providerType === "m365") {
      return <SelectViaM365 initialVia={initialVia} />;
    }
    if (providerType === "cloudflare") {
      return <SelectViaCloudflare initialVia={initialVia} />;
    }
    if (providerType === "alibabacloud") {
      return <SelectViaAlibabaCloud initialVia={initialVia} />;
    }
    return null;
  };

  return <div className="flex flex-col gap-4">{renderSelectComponent()}</div>;
};
