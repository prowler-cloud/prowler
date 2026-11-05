"use client";

import { useRouter } from "next/navigation";

import {
  providerLabel,
  type RealtimeProviderOption,
} from "@/app/(prowler)/realtime/_lib/providers";
import {
  configurationHref,
  realtimeHref,
  type RealtimeTab,
} from "@/app/(prowler)/realtime/_lib/routes";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";

export const REALTIME_VIEW = {
  DASHBOARD: "dashboard",
  CONFIGURATION: "configuration",
} as const;
export type RealtimeView = (typeof REALTIME_VIEW)[keyof typeof REALTIME_VIEW];

interface RealtimeAccountSelectProps {
  providers: RealtimeProviderOption[];
  providerId: string;
  view: RealtimeView;
  /** Dashboard tab to keep when switching accounts. */
  tab?: RealtimeTab;
}

export function RealtimeAccountSelect({
  providers,
  providerId,
  view,
  tab,
}: RealtimeAccountSelectProps) {
  const router = useRouter();

  const goTo = (nextProviderId: string) =>
    router.push(
      view === REALTIME_VIEW.CONFIGURATION
        ? configurationHref(nextProviderId)
        : realtimeHref(nextProviderId, tab),
    );

  return (
    <div className="flex flex-col gap-1.5">
      <span
        id="realtime-account-label"
        className="text-text-neutral-tertiary text-xs"
      >
        AWS account
      </span>
      <Select value={providerId} onValueChange={goTo}>
        <SelectTrigger
          aria-labelledby="realtime-account-label"
          className="min-w-72"
        >
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
