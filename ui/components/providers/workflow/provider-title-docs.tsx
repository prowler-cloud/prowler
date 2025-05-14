import Link from "next/link";

import { getProviderName } from "@/components/ui/entities/get-provider-logo";
import { getProviderLogo } from "@/components/ui/entities/get-provider-logo";
import { ProviderType } from "@/types";

export const ProviderTitleDocs = ({
  providerType,
}: {
  providerType: ProviderType;
}) => {
  const getProviderHelpText = (provider: string) => {
    switch (provider) {
      case "aws":
        return {
          text: "Need help connecting your AWS account?",
          link: "https://goto.prowler.com/provider-aws",
        };
      case "azure":
        return {
          text: "Need help connecting your Azure subscription?",
          link: "https://goto.prowler.com/provider-azure",
        };
      case "m365":
        return {
          text: "Need help connecting your Microsoft 365 account?",
          link: "https://goto.prowler.com/provider-m365",
        };
      case "gcp":
        return {
          text: "Need help connecting your GCP project?",
          link: "https://goto.prowler.com/provider-gcp",
        };
      case "kubernetes":
        return {
          text: "Need help connecting your Kubernetes cluster?",
          link: "https://goto.prowler.com/provider-k8s",
        };
      default:
        return {
          text: "How to setup a provider?",
          link: "https://goto.prowler.com/provider-help",
        };
    }
  };

  return (
    <div className="flex flex-col gap-y-2">
      <div className="flex space-x-4">
        {providerType && getProviderLogo(providerType as ProviderType)}
        <span className="text-lg font-semibold">
          {providerType
            ? getProviderName(providerType as ProviderType)
            : "Unknown Provider"}
        </span>
      </div>
      <div className="flex items-end gap-x-2">
        <p className="text-sm text-default-500">
          {getProviderHelpText(providerType as string).text}
        </p>
        <Link
          href={getProviderHelpText(providerType as string).link}
          target="_blank"
          className="text-sm font-medium text-primary"
        >
          Read the docs
        </Link>
      </div>
    </div>
  );
};
