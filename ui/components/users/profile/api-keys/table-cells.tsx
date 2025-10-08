import { Chip } from "@heroui/chip";

import { ApiKeyData, getApiKeyStatus } from "@/types/api-keys";

import { FALLBACK_VALUES } from "./constants";
import { formatRelativeTime, getStatusColor, getStatusLabel } from "./utils";

export const NameCell = ({ apiKey }: { apiKey: ApiKeyData }) => (
  <p className="text-sm font-medium text-white">
    {apiKey.attributes.name || FALLBACK_VALUES.UNNAMED}
  </p>
);

export const PrefixCell = ({ apiKey }: { apiKey: ApiKeyData }) => (
  <code className="rounded bg-slate-700 px-2 py-1 font-mono text-xs text-slate-300">
    {apiKey.attributes.prefix}
  </code>
);

export const DateCell = ({ date }: { date: string | null }) => (
  <p className="text-sm text-slate-400">{formatRelativeTime(date)}</p>
);

export const LastUsedCell = ({ apiKey }: { apiKey: ApiKeyData }) => (
  <DateCell date={apiKey.attributes.last_used_at} />
);

export const StatusCell = ({ apiKey }: { apiKey: ApiKeyData }) => {
  const status = getApiKeyStatus(apiKey);
  return (
    <Chip color={getStatusColor(status)} size="sm" variant="flat">
      {getStatusLabel(status)}
    </Chip>
  );
};
