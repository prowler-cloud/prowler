import { Tooltip } from "@heroui/tooltip";

import { ProviderType } from "@/types";

import { ConnectionFalse, ConnectionPending, ConnectionTrue } from "../icons";
import { getProviderLogo } from "../ui/entities";

interface ProviderInfoProps {
  connected: boolean | null;
  provider: ProviderType;
  providerAlias: string;
  providerUID?: string;
}

export const ProviderInfo = ({
  connected,
  provider,
  providerAlias,
  providerUID,
}: ProviderInfoProps) => {
  const getIcon = () => {
    switch (connected) {
      case true:
        return (
          <Tooltip content="Provider connected" className="text-xs">
            <div className="rounded-medium border-system-success bg-system-success-lighter flex items-center justify-center border-2 p-1">
              <ConnectionTrue className="text-system-success" size={24} />
            </div>
          </Tooltip>
        );
      case false:
        return (
          <Tooltip content="Provider connection failed" className="text-xs">
            <div className="rounded-medium border-border-error flex items-center justify-center border-2 p-1">
              <ConnectionFalse className="text-text-error-primary" size={24} />
            </div>
          </Tooltip>
        );
      case null:
        return (
          <Tooltip content="Provider not connected" className="text-xs">
            <div className="bg-info-lighter border-info-lighter rounded-medium flex items-center justify-center border p-1">
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
      <div className="flex items-center gap-4">
        <div className="shrink-0">{getProviderLogo(provider)}</div>
        {getIcon()}
        <span className="font-medium">{providerAlias || providerUID}</span>
      </div>
    </div>
  );
};
