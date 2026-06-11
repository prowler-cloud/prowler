import { getProviderLogo } from "@/components/shadcn/entities/get-provider-logo";
import { ProviderType } from "@/types";

import {
  ConnectionFalse,
  ConnectionPending,
  ConnectionTrue,
} from "../../../icons";

interface ProviderConnectionInfoProps {
  connected: boolean | null;
  provider: ProviderType;
  providerAlias: string;
  providerUID?: string;
}

export const ProviderConnectionInfo = ({
  connected,
  provider,
  providerAlias,
  providerUID,
}: ProviderConnectionInfoProps) => {
  const getIcon = () => {
    switch (connected) {
      case true:
        return (
          <div className="border-system-success bg-system-success-lighter flex items-center justify-center rounded-xl border-2 p-1">
            <ConnectionTrue className="text-system-success" size={24} />
          </div>
        );
      case false:
        return (
          <div className="border-border-error flex items-center justify-center rounded-xl border-2 p-1">
            <ConnectionFalse className="text-text-error-primary" size={24} />
          </div>
        );
      case null:
        return (
          <div className="bg-info-lighter border-info-lighter flex items-center justify-center rounded-xl border p-1">
            <ConnectionPending className="text-info" size={24} />
          </div>
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
