import { Chip } from "@heroui/chip";

import { FALLBACK_VALUES } from "./constants";
import { ApiKeyData, getApiKeyStatus, IncludedResource } from "./types";
import {
  formatRelativeTime,
  getApiKeyUserEmail,
  getStatusColor,
  getStatusLabel,
} from "./utils";

export const NameCell = ({ apiKey }: { apiKey: ApiKeyData }) => (
  <p className="text-sm font-medium">
    {apiKey.attributes.name || FALLBACK_VALUES.UNNAMED}
  </p>
);

export const PrefixCell = ({ apiKey }: { apiKey: ApiKeyData }) => (
  <code className="rounded px-2 py-1 font-mono text-xs">
    {apiKey.attributes.prefix}
  </code>
);

export const DateCell = ({ date }: { date: string | null }) => (
  <p className="text-sm">{formatRelativeTime(date)}</p>
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

export const EmailCell = ({
  apiKey,
  included,
}: {
  apiKey: ApiKeyData;
  included?: IncludedResource[];
}) => {
  const email = getApiKeyUserEmail(apiKey, included);
  return <p className="text-sm">{email}</p>;
};
