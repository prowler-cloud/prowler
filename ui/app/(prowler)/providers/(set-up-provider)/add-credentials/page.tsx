import { getProvider } from "@/actions/providers/providers";
import {
  AddViaCredentialsForm,
  AddViaRoleForm,
} from "@/components/providers/workflow/forms";
import { SelectViaAlibabaCloud } from "@/components/providers/workflow/forms/select-credentials-type/alibabacloud";
import { SelectViaAWS } from "@/components/providers/workflow/forms/select-credentials-type/aws";
import { SelectViaCloudflare } from "@/components/providers/workflow/forms/select-credentials-type/cloudflare";
import {
  AddViaServiceAccountForm,
  SelectViaGCP,
} from "@/components/providers/workflow/forms/select-credentials-type/gcp";
import { SelectViaGitHub } from "@/components/providers/workflow/forms/select-credentials-type/github";
import { SelectViaM365 } from "@/components/providers/workflow/forms/select-credentials-type/m365";
import { getProviderFormType } from "@/lib/provider-helpers";
import { ProviderType } from "@/types/providers";

interface Props {
  searchParams: Promise<{ type: ProviderType; id: string; via?: string }>;
}

export default async function AddCredentialsPage({ searchParams }: Props) {
  const resolvedSearchParams = await searchParams;
  const { type: providerType, via, id: providerId } = resolvedSearchParams;
  const formType = getProviderFormType(providerType, via);

  // Fetch provider data to get the UID (needed for OCI)
  let providerUid: string | undefined;
  if (providerId) {
    const formData = new FormData();
    formData.append("id", providerId);
    const providerResponse = await getProvider(formData);
    if (providerResponse?.data?.attributes?.uid) {
      providerUid = providerResponse.data.attributes.uid;
    }
  }

  switch (formType) {
    case "selector":
      if (providerType === "aws") return <SelectViaAWS initialVia={via} />;
      if (providerType === "gcp") return <SelectViaGCP initialVia={via} />;
      if (providerType === "github")
        return <SelectViaGitHub initialVia={via} />;
      if (providerType === "m365") return <SelectViaM365 initialVia={via} />;
      if (providerType === "alibabacloud")
        return <SelectViaAlibabaCloud initialVia={via} />;
      if (providerType === "cloudflare")
        return <SelectViaCloudflare initialVia={via} />;
      return null;

    case "credentials":
      return (
        <AddViaCredentialsForm
          searchParams={resolvedSearchParams}
          providerUid={providerUid}
        />
      );

    case "role":
      return (
        <AddViaRoleForm
          searchParams={resolvedSearchParams}
          providerUid={providerUid}
        />
      );

    case "service-account":
      return (
        <AddViaServiceAccountForm
          searchParams={resolvedSearchParams}
          providerUid={providerUid}
        />
      );

    default:
      return null;
  }
}
