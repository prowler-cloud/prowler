"use client";

import Link from "next/link";

import { getRealtimeFrameworks } from "@/actions/realtime";
import { FrameworkBadges } from "@/components/realtime/framework-badges";
import { PostureTimeline } from "@/components/realtime/posture-timeline";
import {
  DataStoreBadge,
  FeedStatusBadge,
} from "@/components/realtime/realtime-badges";
import { RealtimeSeverity } from "@/components/realtime/realtime-severity";
import {
  CountList,
  StatFigure,
  RealtimeSection,
  RealtimeStatCard,
} from "@/components/realtime/realtime-stat-card";
import {
  PanelFailure,
  PanelLoading,
} from "@/components/realtime/realtime-states";
import { SimulationCard } from "@/components/realtime/simulation-card";
import { useRealtimeInsight } from "@/components/realtime/use-realtime-insight";
import { useRealtimeResource } from "@/components/realtime/use-realtime-resource";
import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import {
  actionStatusBadge,
  anomalyHref,
  detectionStatusBadge,
  formatMoney,
  formatRelativeTime,
  modeLabel,
  orderedSeverities,
  REALTIME_COST_SETTINGS_PATH,
  settingsHref,
} from "@/lib/realtime/display";
import {
  REALTIME_DATA_STORE,
  REALTIME_FEED_SOURCE,
  REALTIME_INSIGHT_KIND,
  REALTIME_MODE,
  type RealtimeOverviewPayload,
} from "@/types/realtime";

const REFRESH_MS = 30_000;

interface OverviewTabProps {
  providerId: string;
  /** Show the sample data instead of the account's. */
  demo?: boolean;
}

function PolicyBadges({
  policy,
  providerId,
}: {
  policy: RealtimeOverviewPayload["policy"];
  providerId: string;
}) {
  if (!policy) {
    return (
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="tag">No policy yet</Badge>
        <span className="text-text-neutral-tertiary text-sm">
          Prowler Realtime only monitors until you save one.
        </span>
        <Button asChild variant="link" size="link-sm">
          <Link href={settingsHref(providerId)}>Set up the policy</Link>
        </Button>
      </div>
    );
  }
  const scoped = Object.keys(policy.scope_tags).length;
  return (
    <ul
      className="flex flex-wrap items-center gap-2"
      aria-label="Policy settings"
    >
      <li>
        <Badge variant={policy.enabled ? "success" : "tag"}>
          {policy.enabled ? "Enabled" : "Disabled"}
        </Badge>
      </li>
      <li>
        <Badge variant="outline">Mode: {modeLabel(policy.mode)}</Badge>
      </li>
      {policy.mode === REALTIME_MODE.AUTO && (
        <li>
          <Badge variant={policy.dry_run ? "info" : "warning"}>
            {policy.dry_run ? "Dry run" : "Live: changes the account"}
          </Badge>
        </li>
      )}
      <li>
        <Badge variant="outline">
          {scoped
            ? `Scope: ${scoped} tag${scoped === 1 ? "" : "s"}`
            : "Scope: whole account"}
        </Badge>
      </li>
      <li>
        <Button asChild variant="link" size="link-sm">
          <Link href={settingsHref(providerId)}>Configure</Link>
        </Button>
      </li>
    </ul>
  );
}

function OverviewFigures({
  overview,
  providerId,
  demo,
}: {
  overview: RealtimeOverviewPayload;
  providerId: string;
  demo: boolean;
}) {
  const { posture, feed, events_last_hour: events, cost } = overview;
  const failing = orderedSeverities(posture.failed_by_severity);
  const dataStoreReady = overview.data_store === REALTIME_DATA_STORE.OK;

  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
      <RealtimeStatCard title="Posture score">
        {posture.has_scan && posture.score !== null ? (
          <StatFigure
            value={`${posture.score}%`}
            caption={`${posture.passed} passing, ${posture.failed} failing`}
          />
        ) : (
          <p className="text-text-neutral-tertiary text-sm">
            No scan has finished for this account yet.
          </p>
        )}
        {failing.length > 0 && (
          <ul className="flex flex-col gap-1" aria-label="Failing by severity">
            {failing.map(([severity, count]) => (
              <li
                key={severity}
                className="flex items-center justify-between gap-2"
              >
                <RealtimeSeverity severity={severity} />
                <span className="text-text-neutral-primary text-sm font-medium tabular-nums">
                  {count}
                </span>
              </li>
            ))}
          </ul>
        )}
      </RealtimeStatCard>

      <RealtimeStatCard
        title="Event feed"
        adornment={feed ? <FeedStatusBadge status={feed.status} /> : undefined}
      >
        {feed ? (
          <>
            <p className="text-text-neutral-primary text-sm">
              {feed.source === REALTIME_FEED_SOURCE.SQS
                ? "Real time, through your SQS queue"
                : "CloudTrail lookup, a few minutes behind"}
            </p>
            <p className="text-text-neutral-tertiary text-xs">
              Last event {formatRelativeTime(feed.last_event_at)}
            </p>
            {feed.last_error && (
              <p className="text-text-error-primary text-xs">
                {feed.last_error}
              </p>
            )}
          </>
        ) : (
          <p className="text-text-neutral-tertiary text-sm">
            No feed is configured yet. Set one up in the Live stream tab.
          </p>
        )}
      </RealtimeStatCard>

      <RealtimeStatCard
        title="Events, last hour"
        adornment={<DataStoreBadge state={overview.data_store} />}
      >
        {dataStoreReady && events ? (
          <StatFigure
            value={events.events}
            caption={`${events.changes} change${events.changes === 1 ? "" : "s"} (writes)`}
          />
        ) : (
          <p className="text-text-neutral-tertiary text-sm">
            {overview.data_store === REALTIME_DATA_STORE.NOT_CONFIGURED
              ? "Real-time data store not configured: the event stream and cost views are off."
              : "The event data store could not be reached."}
          </p>
        )}
      </RealtimeStatCard>

      {cost?.enabled && (
        <RealtimeStatCard title="Cost today">
          {cost.available ? (
            <>
              <StatFigure
                value={formatMoney(cost.today)}
                caption={`${formatMoney(cost.total)} over 30 days`}
              />
              <Badge variant={cost.anomaly_count > 0 ? "warning" : "success"}>
                {cost.anomaly_count > 0
                  ? `${cost.anomaly_count} cost anomal${cost.anomaly_count === 1 ? "y" : "ies"}`
                  : "No cost anomalies"}
              </Badge>
            </>
          ) : (
            <p className="text-text-neutral-tertiary text-sm">
              No cost data yet. It needs the real-time data store and a first
              Cost Explorer fetch.
            </p>
          )}
          {cost.anomalies.length > 0 && (
            <ul className="flex flex-col gap-1" aria-label="Cost anomalies">
              {cost.anomalies.map((anomaly) => (
                <li
                  key={anomaly.id}
                  className="flex items-center justify-between gap-2 text-sm"
                >
                  <Link
                    href={anomalyHref(anomaly.id, providerId, demo)}
                    className="text-button-tertiary truncate underline underline-offset-4"
                    title={`${anomaly.service} in ${anomaly.region}`}
                  >
                    {anomaly.short_service || anomaly.service} ({anomaly.region}
                    )
                  </Link>
                  <span className="text-text-neutral-secondary tabular-nums">
                    {anomaly.ratio}x
                  </span>
                </li>
              ))}
            </ul>
          )}
        </RealtimeStatCard>
      )}

      <RealtimeStatCard title="Detections by status">
        <CountList
          entries={Object.entries(overview.detections)}
          empty="No risky changes detected yet."
          format={(status) => detectionStatusBadge(status).label}
        />
      </RealtimeStatCard>

      <RealtimeStatCard title="Actions by status">
        <CountList
          entries={Object.entries(overview.actions)}
          empty="Prowler Realtime has not acted yet."
          format={(status) => actionStatusBadge(status).label}
        />
      </RealtimeStatCard>

      {!cost?.enabled && (
        <p className="text-text-neutral-tertiary text-sm md:col-span-2 xl:col-span-3">
          Cost anomalies are off &mdash;{" "}
          <Link
            href={settingsHref(providerId, REALTIME_COST_SETTINGS_PATH)}
            className="text-button-tertiary underline underline-offset-4"
          >
            enable them in Configuration
          </Link>
        </p>
      )}
    </div>
  );
}

export function OverviewTab({ providerId, demo = false }: OverviewTabProps) {
  const overview = useRealtimeInsight(
    REALTIME_INSIGHT_KIND.OVERVIEW,
    providerId,
    demo,
    REFRESH_MS,
  );
  const simulation = useRealtimeInsight(
    REALTIME_INSIGHT_KIND.SIMULATION,
    providerId,
    demo,
    REFRESH_MS,
  );
  // Names for the enforced frameworks; ids stand in if the list is unavailable.
  const frameworks = useRealtimeResource(
    () => getRealtimeFrameworks(),
    "frameworks",
  );
  const timeline = useRealtimeInsight(
    REALTIME_INSIGHT_KIND.TIMELINE,
    providerId,
    demo,
    REFRESH_MS,
  );

  return (
    <div className="flex flex-col gap-8">
      <RealtimeSection title="Overview">
        {overview.loading ? (
          <PanelLoading label="Loading the overview" />
        ) : overview.failure ? (
          <PanelFailure
            failure={overview.failure}
            onRetry={overview.reload}
            subject="the overview"
          />
        ) : overview.data ? (
          <div className="flex flex-col gap-4">
            <PolicyBadges
              policy={overview.data.policy}
              providerId={providerId}
            />
            {simulation.data && (
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-text-neutral-secondary text-xs font-medium">
                  Enforced frameworks
                </span>
                <FrameworkBadges
                  frameworks={simulation.data.frameworks}
                  catalog={frameworks.data}
                />
              </div>
            )}
            <OverviewFigures
              overview={overview.data}
              providerId={providerId}
              demo={demo}
            />
          </div>
        ) : null}
      </RealtimeSection>

      <RealtimeSection title="Simulation">
        {simulation.loading ? (
          <PanelLoading label="Loading the simulation" />
        ) : simulation.failure ? (
          <PanelFailure
            failure={simulation.failure}
            onRetry={simulation.reload}
            subject="the simulation"
          />
        ) : simulation.data ? (
          <SimulationCard simulation={simulation.data} />
        ) : null}
      </RealtimeSection>

      <RealtimeSection
        title="Posture timeline"
        description="Passing and failing checks after each scan. Dashed lines mark what Prowler Realtime did."
      >
        {timeline.loading ? (
          <PanelLoading label="Loading the timeline" />
        ) : timeline.failure ? (
          <PanelFailure
            failure={timeline.failure}
            onRetry={timeline.reload}
            subject="the timeline"
          />
        ) : timeline.data ? (
          <PostureTimeline timeline={timeline.data} />
        ) : null}
      </RealtimeSection>
    </div>
  );
}
