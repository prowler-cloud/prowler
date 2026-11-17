import {
  getRealtimeDemo,
  getRealtimeEvents,
  getRealtimeFeed,
} from "@/app/(prowler)/realtime/_actions";
import { RealtimePanelError } from "@/app/(prowler)/realtime/_components/shared/realtime-panel-error";
import { getOverview } from "@/app/(prowler)/realtime/_lib/cached";
import {
  firstParam,
  REALTIME_PARAM,
} from "@/app/(prowler)/realtime/_lib/routes";
import type { RealtimeEvent } from "@/app/(prowler)/realtime/_types";
import type { RealtimeTabProps } from "@/app/(prowler)/realtime/_types/view";
import { Skeleton } from "@/components/shadcn";

import { FeedStatusCard } from "./feed-status-card";
import { StreamView } from "./stream-view";

const STREAM_LIMIT = 200;

/** Changes only drops read-only calls, as the API's `writes_only` does. */
const changesOnly = (events: RealtimeEvent[]): RealtimeEvent[] =>
  events.filter((event) => !event.read_only);

export async function StreamTab({
  providerId,
  demo,
  canManage,
  searchParams,
}: RealtimeTabProps) {
  const showAll = firstParam(searchParams, REALTIME_PARAM.ALL_EVENTS) === "1";
  const [overviewResult, feedResult, eventsResult] = await Promise.all([
    getOverview(providerId, demo),
    demo ? null : getRealtimeFeed(providerId),
    demo
      ? getRealtimeDemo("events").then((result) =>
          result.ok
            ? {
                ok: true as const,
                data: showAll
                  ? result.data.items
                  : changesOnly(result.data.items),
              }
            : result,
        )
      : getRealtimeEvents({
          providerId,
          limit: STREAM_LIMIT,
          writesOnly: !showAll,
        }),
  ]);
  const overview = overviewResult.ok ? overviewResult.data : null;
  const feed = feedResult?.ok ? feedResult.data : null;

  return (
    <div className="flex flex-col gap-4">
      <FeedStatusCard
        providerId={providerId}
        feed={overview?.feed ?? null}
        feedId={feed?.id ?? null}
        lastPolledAt={feed?.last_polled_at ?? null}
        eventsLastHour={overview?.events_last_hour ?? null}
        canWrite={canManage && !demo}
        demo={demo}
      />
      {eventsResult.ok ? (
        <StreamView
          providerId={providerId}
          events={eventsResult.data}
          showAll={showAll}
        />
      ) : (
        <RealtimePanelError failure={eventsResult} />
      )}
    </div>
  );
}

export function StreamTabSkeleton() {
  return (
    <div className="flex flex-col gap-4" aria-hidden="true">
      <Skeleton className="h-[76px] w-full rounded-xl" />
      <Skeleton className="h-8 w-80 rounded-lg" />
      <Skeleton className="h-[520px] w-full rounded-xl" />
    </div>
  );
}
