import { Settings2 } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

import {
  formatRelativeTime,
  modeLabel,
} from "@/app/(prowler)/realtime/_lib/display";
import type { RealtimeProviderOption } from "@/app/(prowler)/realtime/_lib/providers";
import {
  configurationHref,
  type RealtimeTab,
} from "@/app/(prowler)/realtime/_lib/routes";
import {
  REALTIME_DATA_STORE,
  REALTIME_FEED_SOURCE,
  REALTIME_FEED_STATUS,
  REALTIME_MODE,
  type RealtimeOverviewPayload,
  type RealtimePolicy,
} from "@/app/(prowler)/realtime/_types";
import { Badge, Button, Card, CardContent } from "@/components/shadcn";

import {
  REALTIME_VIEW,
  RealtimeAccountSelect,
} from "./realtime-account-select";
import { RealtimeShareStatus } from "./realtime-share-status";

interface RealtimeAccountHeaderProps {
  providers: RealtimeProviderOption[];
  providerId: string;
  tab: RealtimeTab;
  policy: RealtimePolicy | null;
  overview: RealtimeOverviewPayload | null;
  frameworkNames: string[];
  canManage: boolean;
  demo: boolean;
}

interface StatusItemProps {
  label: string;
  children: ReactNode;
}

function StatusItem({ label, children }: StatusItemProps) {
  return (
    <div className="flex flex-col gap-1.5">
      <span className="text-text-neutral-tertiary text-xs">{label}</span>
      <div className="flex flex-wrap items-center gap-1.5">{children}</div>
    </div>
  );
}

function AccountStatus({
  policy,
  demo,
}: Pick<RealtimeAccountHeaderProps, "policy" | "demo">) {
  if (demo || !policy) return <Badge variant="tag">Not set up</Badge>;
  return policy.enabled ? (
    <Badge variant="success">Active</Badge>
  ) : (
    <Badge variant="warning">Paused</Badge>
  );
}

function FeedStatus({
  overview,
}: Pick<RealtimeAccountHeaderProps, "overview">) {
  const feed = overview?.feed;
  if (!feed) return <Badge variant="tag">No feed yet</Badge>;
  if (feed.status === REALTIME_FEED_STATUS.ERROR) {
    return <Badge variant="error">Feed error</Badge>;
  }
  if (feed.status === REALTIME_FEED_STATUS.NOT_CONFIGURED) {
    return <Badge variant="tag">Waiting for the first poll</Badge>;
  }
  const source =
    feed.source === REALTIME_FEED_SOURCE.SQS
      ? "Live via SQS"
      : "CloudTrail lookup, minutes behind";
  return (
    <Badge variant="success">
      {source} · last event {formatRelativeTime(feed.last_event_at)}
    </Badge>
  );
}

/** Account picker and what Realtime is doing for it, at a glance. */
export function RealtimeAccountHeader({
  providers,
  providerId,
  tab,
  policy,
  overview,
  frameworkNames,
  canManage,
  demo,
}: RealtimeAccountHeaderProps) {
  const scopeTags = Object.entries(policy?.scope_tags ?? {});
  const dataStore = overview?.data_store;

  return (
    <Card variant="base" padding="lg">
      <CardContent className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div className="flex flex-col gap-4 md:flex-row md:flex-wrap md:items-end md:gap-6">
          <RealtimeAccountSelect
            providers={providers}
            providerId={providerId}
            view={REALTIME_VIEW.DASHBOARD}
            tab={tab}
          />
          <div className="flex flex-wrap gap-x-6 gap-y-3">
            <StatusItem label="Status">
              <AccountStatus policy={policy} demo={demo} />
              {!canManage && <Badge variant="outline">Read only</Badge>}
            </StatusItem>
            {policy && (
              <StatusItem label="Response">
                <Badge variant="tag">{modeLabel(policy.mode)}</Badge>
                {policy.mode === REALTIME_MODE.AUTO &&
                  (policy.dry_run ? (
                    <Badge variant="warning">Dry run</Badge>
                  ) : (
                    <Badge variant="error">Changes the account</Badge>
                  ))}
              </StatusItem>
            )}
            {!demo && (
              <StatusItem label="Event feed">
                <FeedStatus overview={overview} />
                {dataStore && dataStore !== REALTIME_DATA_STORE.OK && (
                  <Badge variant="warning">Event store unavailable</Badge>
                )}
              </StatusItem>
            )}
            {policy && (
              <StatusItem label="Scope">
                {scopeTags.length ? (
                  scopeTags.map(([key, value]) => (
                    <Badge key={key} variant="tag">
                      {key} = {value}
                    </Badge>
                  ))
                ) : (
                  <Badge variant="tag">Whole account</Badge>
                )}
              </StatusItem>
            )}
            {policy && (
              <StatusItem label="Compliance frameworks">
                {frameworkNames.length ? (
                  frameworkNames.map((name) => (
                    <Badge key={name} variant="tag">
                      {name}
                    </Badge>
                  ))
                ) : (
                  <Badge variant="tag">Every check</Badge>
                )}
              </StatusItem>
            )}
          </div>
        </div>
        <div className="flex shrink-0 flex-wrap gap-2">
          <RealtimeShareStatus providerId={providerId} demo={demo} />
          {!demo && (
            <Button variant="outline" asChild>
              <Link href={configurationHref(providerId)}>
                <Settings2 aria-hidden />
                Configure
              </Link>
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
