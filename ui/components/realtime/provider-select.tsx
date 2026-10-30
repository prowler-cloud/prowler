"use client";

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";
import {
  providerLabel,
  type RealtimeProviderOption,
} from "@/lib/realtime/providers";

interface ProviderSelectProps {
  providers: RealtimeProviderOption[];
  value: string;
  onChange: (providerId: string) => void;
}

/** The AWS account picker every Realtime page shares; `?provider=` keeps the choice. */
export function ProviderSelect({
  providers,
  value,
  onChange,
}: ProviderSelectProps) {
  return (
    <div className="flex max-w-md min-w-64 flex-1 flex-col gap-1.5">
      <label
        htmlFor="realtime-provider"
        className="text-text-neutral-tertiary text-xs font-medium"
      >
        AWS account
      </label>
      <Select value={value} onValueChange={onChange}>
        <SelectTrigger id="realtime-provider" size="sm">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {providers.map((provider) => (
            <SelectItem key={provider.id} value={provider.id}>
              {providerLabel(provider)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}

/** Write the selection to the URL without a navigation, so a view can be shared. */
export const syncProviderToUrl = (next: {
  provider?: string;
  tab?: string;
}) => {
  const params = new URLSearchParams(window.location.search);
  if (next.provider) params.set("provider", next.provider);
  if (next.tab) params.set("tab", next.tab);
  window.history.replaceState(null, "", `?${params.toString()}`);
};
