import React from "react";

import {
  AWSProviderBadge,
  AzureProviderBadge,
  GCPProviderBadge,
  KS8ProviderBadge,
} from "../icons/providers-badge";
import { SnippetIdProvider } from "./snippet-id-provider";

interface ProviderInfoProps {
  connected: boolean | null;
  provider: "aws" | "azure" | "gcp" | "kubernetes";
  providerAlias: string;
  providerId: string;
}

export const ProviderInfoShort: React.FC<ProviderInfoProps> = ({
  provider,
  providerAlias,
  providerId,
}) => {
  const getProviderLogo = () => {
    switch (provider) {
      case "aws":
        return <AWSProviderBadge width={35} height={35} />;
      case "azure":
        return <AzureProviderBadge width={35} height={35} />;
      case "gcp":
        return <GCPProviderBadge width={35} height={35} />;
      case "kubernetes":
        return <KS8ProviderBadge width={35} height={35} />;
      default:
        return null;
    }
  };

  return (
    <div className="max-w-full">
      <div className="flex items-center justify-between space-x-4">
        <div className="flex items-center space-x-4">
          <div className="flex-shrink-0">{getProviderLogo()}</div>
          <div className="flex flex-col">
            <span className="text-md font-semibold">{providerAlias}</span>
            <SnippetIdProvider className="h-5" providerId={providerId} />
          </div>
        </div>
      </div>
    </div>
  );
};
