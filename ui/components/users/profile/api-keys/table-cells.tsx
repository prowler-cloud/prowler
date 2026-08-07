import {
  Badge,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn";

import { FALLBACK_VALUES } from "./constants";
import { EnrichedApiKey, getApiKeyStatus } from "./types";
import { formatRelativeTime, getStatusColor, getStatusLabel } from "./utils";

// Maps HeroUI status colors to shadcn Badge variants
const STATUS_BADGE_VARIANT = {
  success: "success",
  danger: "error",
  warning: "warning",
} as const;

export const NameCell = ({ apiKey }: { apiKey: EnrichedApiKey }) => {
  const name = apiKey.attributes.name || FALLBACK_VALUES.UNNAMED;

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <p className="w-64 truncate text-sm font-medium whitespace-nowrap">
          {name}
        </p>
      </TooltipTrigger>
      <TooltipContent>{name}</TooltipContent>
    </Tooltip>
  );
};

export const PrefixCell = ({ apiKey }: { apiKey: EnrichedApiKey }) => (
  <code className="rounded px-2 py-1 font-mono text-xs">
    {apiKey.attributes.prefix}
  </code>
);

export const DateCell = ({ date }: { date: string | null }) => (
  <p className="text-sm whitespace-nowrap">{formatRelativeTime(date)}</p>
);

export const LastUsedCell = ({ apiKey }: { apiKey: EnrichedApiKey }) => (
  <DateCell date={apiKey.attributes.last_used_at} />
);

export const StatusCell = ({ apiKey }: { apiKey: EnrichedApiKey }) => {
  const status = getApiKeyStatus(apiKey);
  return (
    <Badge variant={STATUS_BADGE_VARIANT[getStatusColor(status)]}>
      {getStatusLabel(status)}
    </Badge>
  );
};

export const EmailCell = ({ apiKey }: { apiKey: EnrichedApiKey }) => (
  <p className="text-sm">{apiKey.userEmail}</p>
);
