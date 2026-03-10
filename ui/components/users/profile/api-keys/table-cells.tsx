import { Chip } from "@heroui/chip";

import { FALLBACK_VALUES } from "./constants";
import { EnrichedApiKey, getApiKeyStatus } from "./types";
import { formatRelativeTime, getStatusColor, getStatusLabel } from "./utils";

export const NameCell = ({ apiKey }: { apiKey: EnrichedApiKey }) => (
  <p className="text-sm font-medium">
    {apiKey.attributes.name || FALLBACK_VALUES.UNNAMED}
  </p>
);

export const PrefixCell = ({ apiKey }: { apiKey: EnrichedApiKey }) => (
  <code className="rounded px-2 py-1 font-mono text-xs">
    {apiKey.attributes.prefix}
  </code>
);

export const DateCell = ({ date }: { date: string | null }) => (
  <p className="text-sm">{formatRelativeTime(date)}</p>
);

export const LastUsedCell = ({ apiKey }: { apiKey: EnrichedApiKey }) => (
  <DateCell date={apiKey.attributes.last_used_at} />
);

export const StatusCell = ({ apiKey }: { apiKey: EnrichedApiKey }) => {
  const status = getApiKeyStatus(apiKey);
  return (
    <Chip color={getStatusColor(status)} size="sm" variant="flat">
      {getStatusLabel(status)}
    </Chip>
  );
};

export const EmailCell = ({ apiKey }: { apiKey: EnrichedApiKey }) => (
  <p className="text-sm">{apiKey.userEmail}</p>
);
