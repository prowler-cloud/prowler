"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { pollRealtimeFeed } from "@/app/(prowler)/realtime/_actions";
import { RealtimeBadge } from "@/app/(prowler)/realtime/_components/shared/realtime-badge";
import {
  DEMO_TOOLTIP,
  NO_PERMISSION_TOOLTIP,
} from "@/app/(prowler)/realtime/_lib/demo";
import {
  feedStatusBadge,
  formatRelativeTime,
} from "@/app/(prowler)/realtime/_lib/display";
import { configurationHref } from "@/app/(prowler)/realtime/_lib/routes";
import {
  REALTIME_FEED_SOURCE,
  type RealtimeEventStats,
  type RealtimeOverviewFeed,
} from "@/app/(prowler)/realtime/_types";
import {
  Button,
  Card,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
  useToast,
} from "@/components/shadcn";

interface FeedStatusCardProps {
  providerId: string;
  feed: RealtimeOverviewFeed | null;
  feedId: string | null;
  lastPolledAt: string | null;
  eventsLastHour: RealtimeEventStats | null;
  canWrite: boolean;
  demo: boolean;
}

/** Where events come from, how fresh they are, and a way to check now. */
export function FeedStatusCard({
  providerId,
  feed,
  feedId,
  lastPolledAt,
  eventsLastHour,
  canWrite,
  demo,
}: FeedStatusCardProps) {
  const router = useRouter();
  const { toast } = useToast();
  const [checking, setChecking] = useState(false);

  if (!feed) {
    return (
      <Card
        variant="base"
        className="flex-row flex-wrap items-center justify-between gap-4"
      >
        <div className="flex flex-col gap-1">
          <span className="text-text-neutral-primary text-sm font-semibold">
            No event feed yet
          </span>
          <span className="text-text-neutral-tertiary text-sm">
            Set up the feed so Prowler can read this account&apos;s CloudTrail
            events.
          </span>
        </div>
        <Button variant="outline" size="sm" asChild>
          <Link href={configurationHref(providerId, "feed")}>Set up feed</Link>
        </Button>
      </Card>
    );
  }

  const checkNow = async () => {
    if (!feedId) return;
    setChecking(true);
    const result = await pollRealtimeFeed(feedId);
    setChecking(false);
    if (!result.ok) {
      toast({
        variant: "destructive",
        title: "The feed could not be checked",
        description: result.error,
      });
      return;
    }
    toast({
      title: "Checking the feed…",
      description: "New events show up here in a few seconds.",
    });
    router.refresh();
  };

  const source =
    feed.source === REALTIME_FEED_SOURCE.SQS
      ? "Real time through SQS"
      : "CloudTrail lookup, a few minutes behind";
  const disabledReason = demo
    ? DEMO_TOOLTIP
    : !canWrite
      ? NO_PERMISSION_TOOLTIP
      : null;
  const checkButton = (
    <Button
      variant="outline"
      size="sm"
      onClick={checkNow}
      disabled={Boolean(disabledReason) || !feedId || checking}
    >
      {checking ? "Checking…" : "Check now"}
    </Button>
  );

  return (
    <Card variant="base" className="gap-3">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-x-8 gap-y-3">
          <div className="flex flex-col gap-1">
            <RealtimeBadge descriptor={feedStatusBadge(feed.status)} />
            <span className="text-text-neutral-tertiary text-xs">{source}</span>
          </div>
          {lastPolledAt && (
            <Stat label="Last poll" value={formatRelativeTime(lastPolledAt)} />
          )}
          <Stat
            label="Last event"
            value={formatRelativeTime(feed.last_event_at)}
          />
          {eventsLastHour && (
            <Stat
              label="Last hour"
              value={`${eventsLastHour.events.toLocaleString()} events · ${eventsLastHour.changes.toLocaleString()} changes`}
            />
          )}
        </div>
        {disabledReason ? (
          <Tooltip>
            <TooltipTrigger asChild>
              <span tabIndex={0} className="inline-flex">
                {checkButton}
              </span>
            </TooltipTrigger>
            <TooltipContent>{disabledReason}</TooltipContent>
          </Tooltip>
        ) : (
          checkButton
        )}
      </div>
      {feed.last_error && (
        <p className="text-text-error-primary text-sm">
          The last poll failed: {feed.last_error}
        </p>
      )}
    </Card>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-text-neutral-tertiary text-xs">{label}</span>
      {/* Relative times drift between server and client render. */}
      <span
        className="text-text-neutral-primary text-sm font-medium"
        suppressHydrationWarning
      >
        {value}
      </span>
    </div>
  );
}
