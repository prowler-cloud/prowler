import { getConnectionStatus } from "@/app/(prowler)/lighthouse/_lib/config";
import { formatLastChecked } from "@/app/(prowler)/lighthouse/_lib/format";
import {
  type LighthouseV2Configuration,
  type LighthouseV2ProviderType,
  type LighthouseV2SupportedProvider,
} from "@/app/(prowler)/lighthouse/_types";
import { Card } from "@/components/shadcn/card/card";
import { cn } from "@/lib/utils";

import { ProviderIcon } from "./provider-icon";
import { StatusBadge } from "./status-badge";

export function LighthouseV2ProviderRail({
  configurations,
  providers,
  selectedProvider,
  onSelectProvider,
}: {
  configurations: LighthouseV2Configuration[];
  providers: LighthouseV2SupportedProvider[];
  selectedProvider: LighthouseV2ProviderType;
  onSelectProvider: (provider: LighthouseV2ProviderType) => void;
}) {
  return (
    <Card variant="inner" padding="none" className="min-w-0 p-4 md:p-5">
      <aside className="flex min-w-0 flex-col gap-3">
        <div className="flex items-center justify-between gap-3 px-1">
          <div>
            <h3 className="text-text-neutral-primary text-sm font-semibold">
              Providers
            </h3>
            <p className="text-text-neutral-secondary text-xs">
              Choose provider to configure
            </p>
          </div>
        </div>
        <div className="flex flex-col gap-2">
          {providers.map((provider) => {
            const config = configurations.find(
              (item) => item.providerType === provider.id,
            );
            const active = provider.id === selectedProvider;
            const status = getConnectionStatus(config);

            return (
              <button
                key={provider.id}
                type="button"
                aria-label={provider.name}
                aria-pressed={active}
                onClick={() => onSelectProvider(provider.id)}
                className={cn(
                  "border-border-neutral-secondary bg-bg-neutral-secondary hover:bg-bg-neutral-tertiary group flex min-w-0 items-start gap-3 rounded-[12px] border p-3 text-left transition-colors",
                  active &&
                    "border-border-input-primary-press bg-bg-neutral-tertiary ring-border-input-primary-press ring-1",
                )}
              >
                <div className="border-border-neutral-secondary bg-bg-neutral-tertiary flex size-10 shrink-0 items-center justify-center rounded-[9px] border">
                  <ProviderIcon
                    provider={provider.id}
                    className="text-text-neutral-secondary size-5"
                  />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex min-w-0 items-center justify-between gap-2">
                    <span className="text-text-neutral-primary truncate text-sm font-medium">
                      {provider.name}
                    </span>
                    <StatusBadge status={status} />
                  </div>
                  <p className="text-text-neutral-tertiary mt-1 text-xs">
                    {formatLastChecked(config?.connectionLastCheckedAt)}
                  </p>
                </div>
              </button>
            );
          })}
        </div>
      </aside>
    </Card>
  );
}
