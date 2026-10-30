"use client";

import Link from "next/link";
import { useId, useState } from "react";

import { getRealtimeDemo, getRealtimeEvents } from "@/actions/realtime";
import { EventsTable } from "@/components/realtime/events-table";
import { RealtimeSection } from "@/components/realtime/realtime-stat-card";
import {
  PanelFailure,
  PanelLoading,
} from "@/components/realtime/realtime-states";
import { useRealtimeResource } from "@/components/realtime/use-realtime-resource";
import { Switch } from "@/components/shadcn/switch/switch";
import { settingsHref } from "@/lib/realtime/display";

const STREAM_REFRESH_MS = 5_000;
const STREAM_LIMIT = 100;

interface StreamTabProps {
  providerId: string;
  /** Show the sample events instead of the account's. */
  demo?: boolean;
}

export function StreamTab({ providerId, demo = false }: StreamTabProps) {
  const writesId = useId();
  const liveId = useId();
  const [writesOnly, setWritesOnly] = useState(true);
  const [live, setLive] = useState(true);

  // The sample is one fixed page: the filter is applied here, nothing refreshes.
  const events = useRealtimeResource(
    async () => {
      if (!demo) {
        return getRealtimeEvents({
          providerId,
          limit: STREAM_LIMIT,
          writesOnly,
        });
      }
      const result = await getRealtimeDemo("events");
      return result.ok
        ? {
            ok: true as const,
            data: result.data.items.filter(
              (event) => !writesOnly || !event.read_only,
            ),
          }
        : result;
    },
    demo ? `demo:events:${writesOnly}` : `events:${providerId}:${writesOnly}`,
    { intervalMs: live && !demo ? STREAM_REFRESH_MS : undefined },
  );

  return (
    <div className="flex flex-col gap-8">
      <RealtimeSection
        title="Live CloudTrail stream"
        description="The last 24 hours of API calls, newest first, with the detection each one raised."
        action={
          <div className="flex flex-wrap items-center gap-4">
            <div className="flex items-center gap-2">
              <Switch
                id={writesId}
                checked={writesOnly}
                onCheckedChange={setWritesOnly}
              />
              <label
                htmlFor={writesId}
                className="text-text-neutral-secondary text-sm"
              >
                Changes only
              </label>
            </div>
            <div className="flex items-center gap-2">
              <Switch
                id={liveId}
                checked={live && !demo}
                disabled={demo}
                onCheckedChange={setLive}
              />
              <label
                htmlFor={liveId}
                className="text-text-neutral-secondary text-sm"
              >
                Auto-refresh ({STREAM_REFRESH_MS / 1000}s)
              </label>
            </div>
          </div>
        }
      >
        <div>
          {events.loading ? (
            <PanelLoading label="Loading events" />
          ) : events.failure ? (
            <PanelFailure
              failure={events.failure}
              onRetry={events.reload}
              subject="the event stream"
            />
          ) : events.data ? (
            <EventsTable events={events.data} writesOnly={writesOnly} />
          ) : null}
        </div>
      </RealtimeSection>

      <p className="text-text-neutral-tertiary text-sm">
        The event feed (real-time queue or CloudTrail lookup) is set up in{" "}
        <Link
          href={settingsHref(providerId)}
          className="text-button-tertiary underline underline-offset-4"
        >
          Configuration
        </Link>
        .
      </p>
    </div>
  );
}
