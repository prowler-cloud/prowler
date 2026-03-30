import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { ProviderType } from "@/types";

import { ProviderIconCell } from "./provider-icon-cell";

const MAX_VISIBLE_PROVIDERS = 3;

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
      {visible.map((provider) => (
        <ProviderIconCell
          key={provider}
          provider={provider}
          size={28}
          className="size-7"
        />
      ))}
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
