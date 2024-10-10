import React from "react";

import { ConnectionIcon } from "../icons";
import {
  AWSProviderBadge,
  AzureProviderBadge,
  GCPProviderBadge,
  KS8ProviderBadge,
} from "../icons/providers-badge";

interface ProviderInfoProps {
  connected: boolean | null;
  provider: "aws" | "azure" | "gcp" | "kubernetes";
  providerAlias: string;
}

export const ProviderInfo: React.FC<ProviderInfoProps> = ({
  connected,
  provider,
  providerAlias,
}) => {
  const getIcon = () => {
    switch (connected) {
      case true:
        return (
          <div className="flex items-center justify-center rounded-medium border border-system-success bg-system-success-lighter p-1">
            <ConnectionIcon className="text-system-success" size={24} />
          </div>
        );
      case false:
        return (
          <div className="flex items-center justify-center rounded-medium border border-danger bg-system-error-lighter p-1">
            <ConnectionIcon className="text-danger" size={24} />
          </div>
        );
      case null:
        return (
          <div className="bg-info-lighter border-info-lighter flex items-center justify-center rounded-medium border p-1">
            <ConnectionIcon className="text-info" size={24} />
          </div>
        );
      default:
        return <ConnectionIcon size={24} />;
    }
  };

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
    <div className="max-w-48">
      <div className="flex items-center justify-between space-x-4">
        <div className="flex items-center space-x-4">
          <div className="flex-shrink-0">{getProviderLogo()}</div>
          <div className="flex-shrink-0">{getIcon()}</div>
          <div className="flex flex-col">
            <span className="text-md max-w-24 overflow-hidden text-ellipsis font-semibold lg:max-w-36">
              {providerAlias}
            </span>
            {/* <CustomLoader size="small" /> */}
          </div>
        </div>
      </div>
    </div>
  );
};
