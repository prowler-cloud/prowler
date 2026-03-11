import { ProviderType } from "@/types";

import { getProviderLogo } from "../ui/entities";

interface ProviderInfoProps {
  provider: ProviderType;
  providerAlias: string | null;
  providerUID?: string;
}

export const ProviderInfo = ({
  provider,
  providerAlias,
  providerUID,
}: ProviderInfoProps) => {
  return (
    <div className="flex min-w-0 items-center text-sm">
      <div className="flex min-w-0 items-center gap-4">
        <div className="shrink-0">{getProviderLogo(provider)}</div>
        <div className="flex min-w-0 flex-col gap-0.5">
          <span className="truncate font-medium">
            {providerAlias || providerUID}
          </span>
          {providerUID && (
            <span className="text-text-neutral-tertiary truncate text-xs">
              UID: {providerUID}
            </span>
          )}
        </div>
      </div>
    </div>
  );
};
