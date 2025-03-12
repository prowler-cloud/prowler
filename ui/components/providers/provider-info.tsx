import React from "react";

import { ConnectionFalse, ConnectionPending, ConnectionTrue } from "../icons";
import { getProviderLogo } from "../ui/entities";

interface ProviderInfoProps {
  connected: boolean | null;
  provider: "aws" | "azure" | "gcp" | "kubernetes";
  providerAlias: string;
  providerUID?: string;
}

export const ProviderInfo: React.FC<ProviderInfoProps> = ({
  connected,
  provider,
  providerAlias,
  providerUID,
}) => {
  const getIcon = () => {
    switch (connected) {
      case true:
        return (
          <div className="flex items-center justify-center rounded-medium border-2 border-system-success bg-system-success-lighter p-1">
            <ConnectionTrue className="text-system-success" size={24} />
          </div>
        );
      case false:
        return (
          <div className="flex items-center justify-center rounded-medium border-2 border-danger bg-system-error-lighter p-1">
            <ConnectionFalse className="text-danger" size={24} />
          </div>
        );
      case null:
        return (
          <div className="bg-info-lighter border-info-lighter flex items-center justify-center rounded-medium border p-1">
            <ConnectionPending className="text-info" size={24} />
          </div>
        );
      default:
        return <ConnectionPending size={24} />;
    }
  };

  return (
    <div className="dark:bg-prowler-blue-400">
      <div className="grid grid-cols-1">
        <div className="flex items-center text-sm">
          <div className="flex items-center">
            <span className="flex items-center justify-center px-4">
              {getProviderLogo(provider)}
            </span>
            <div className="flex items-center space-x-4">
              <div className="flex-shrink-0">{getIcon()}</div>
              <span className="font-medium">
                {providerAlias || providerUID}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
