import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { ProviderType } from "@/types";

import { PROVIDER_ICONS } from "./provider-icon-cell";

const MAX_VISIBLE_PROVIDERS = 3;
const ICON_SIZE = 28;

interface ImpactedProvidersCellProps {
  providers: ProviderType[];
}

export const ImpactedProvidersCell = ({
  providers,
}: ImpactedProvidersCellProps) => {
  if (!providers.length) {
    return <span className="text-text-neutral-tertiary text-sm">-</span>;
  }

  const visible = providers.slice(0, MAX_VISIBLE_PROVIDERS);
  const remaining = providers.length - MAX_VISIBLE_PROVIDERS;

  return (
    <div className="flex items-center gap-1">
      {visible.map((provider) => {
        const IconComponent = PROVIDER_ICONS[provider];

        if (!IconComponent) {
          return (
            <div
              key={provider}
              className="flex size-7 items-center justify-center"
            >
              <span className="text-text-neutral-secondary text-xs">?</span>
            </div>
          );
        }

        return (
          <div
            key={provider}
            className="flex size-7 items-center justify-center overflow-hidden"
          >
            <IconComponent width={ICON_SIZE} height={ICON_SIZE} />
          </div>
        );
      })}
      {remaining > 0 && (
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="text-text-neutral-tertiary cursor-default text-xs font-medium">
              +{remaining}
            </span>
          </TooltipTrigger>
          <TooltipContent>
            <span className="text-xs">
              {providers.slice(MAX_VISIBLE_PROVIDERS).join(", ")}
            </span>
          </TooltipContent>
        </Tooltip>
      )}
    </div>
  );
};
