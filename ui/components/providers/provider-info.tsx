import { Tooltip } from "@nextui-org/react";
import React from "react";

import { ProviderType } from "@/types";

import { ConnectionFalse, ConnectionPending, ConnectionTrue } from "../icons";
import { getProviderLogo } from "../ui/entities";
interface ProviderInfoProps {
  connected: boolean | null;
  provider: ProviderType;
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
          <Tooltip content="Provider connected" className="text-xs">
            <div className="flex items-center justify-center rounded-medium border-2 border-system-success bg-system-success-lighter p-1">
              <ConnectionTrue className="text-system-success" size={24} />
            </div>
          </Tooltip>
        );
      case false:
        return (
          <Tooltip content="Provider connection failed" className="text-xs">
            <div className="flex items-center justify-center rounded-medium border-2 border-danger bg-system-error-lighter p-1">
              <ConnectionFalse className="text-danger" size={24} />
            </div>
          </Tooltip>
        );
      case null:
        return (
          <Tooltip content="Provider not connected" className="text-xs">
            <div className="bg-info-lighter border-info-lighter flex items-center justify-center rounded-medium border p-1">
              <ConnectionPending className="text-info" size={24} />
            </div>
          </Tooltip>
        );
      default:
        return <ConnectionPending size={24} />;
    }
  };

  return (
    <div className="flex items-center text-sm">
      <div className="flex items-center space-x-4">
        {getProviderLogo(provider)}
        {getIcon()}
        <span className="font-medium">{providerAlias || providerUID}</span>
      </div>
    </div>
  );
};
