import Link from "next/link";

import { RealtimeBadge } from "@/app/(prowler)/realtime/_components/shared/realtime-badge";
import { RealtimePanelError } from "@/app/(prowler)/realtime/_components/shared/realtime-panel-error";
import {
  formatChange,
  formatDateTime,
  formatMoney,
  routeBadge,
  shortArn,
} from "@/app/(prowler)/realtime/_lib/display";
import { checkFindingsHref } from "@/app/(prowler)/realtime/_lib/routes";
import type {
  RealtimeAnomalyPayload,
  RealtimeCostThresholds,
  RealtimeResult,
} from "@/app/(prowler)/realtime/_types";
import { Badge } from "@/components/shadcn";

import { AnomalyChart, baselineOf } from "./anomaly-chart";

interface AnomalyDetailProps {
  result: RealtimeResult<RealtimeAnomalyPayload> | null;
  fallbackThresholds: RealtimeCostThresholds;
}

/** One cost anomaly in the side panel: the spike, recent changes and findings. */
export function AnomalyDetail({
  result,
  fallbackThresholds,
}: AnomalyDetailProps) {
  if (!result) return null;
  if (!result.ok) {
    return result.status === 404 ? (
      <p className="text-text-neutral-tertiary p-4 text-sm">
        This anomaly is no longer active: spend is back under the thresholds, or
        cost anomalies were turned off.
      </p>
    ) : (
      <div className="p-4">
        <RealtimePanelError failure={result} />
      </div>
    );
  }

  const { anomaly, series, events, findings } = result.data;
  const thresholds = result.data.thresholds ?? fallbackThresholds;
  const baseline = anomaly?.base ?? baselineOf(series);
  const title = anomaly?.short_service || result.data.short_service;

  return (
    <div className="flex h-full min-h-0 flex-col gap-5 overflow-y-auto p-4">
      <div className="flex flex-col gap-2">
        <div className="flex flex-wrap items-center gap-2">
          {anomaly ? (
            <Badge variant="warning">Anomaly</Badge>
          ) : (
            <Badge variant="success">Back to normal</Badge>
          )}
          {anomaly && (
            <span className="text-text-warning-primary text-sm font-semibold">
              {formatChange(anomaly.ratio, anomaly.delta)}
            </span>
          )}
        </div>
        <h3 className="text-text-neutral-primary text-lg font-semibold">
          {title}
        </h3>
        {anomaly && (
          <p className="text-text-neutral-tertiary text-xs">
            {anomaly.region} · latest day {formatMoney(anomaly.today)} against a
            baseline of {formatMoney(anomaly.base)}
          </p>
        )}
      </div>

      <AnomalyChart
        series={series}
        baseline={baseline}
        thresholds={thresholds}
        label={`Daily spend of ${title}`}
      />

      <section className="flex flex-col gap-2">
        <h4 className="text-text-neutral-primary text-sm font-semibold">
          Recent changes in this service
        </h4>
        {events.length === 0 ? (
          <p className="text-text-neutral-tertiary text-sm">
            No write calls in the last 48 hours.
          </p>
        ) : (
          <ul className="flex flex-col">
            {events.map((event) => (
              <li
                key={event.event_id}
                className="border-border-neutral-secondary flex flex-col gap-0.5 border-t py-2 first:border-t-0"
              >
                <span className="text-text-neutral-primary font-mono text-xs">
                  {event.event_name}
                </span>
                <span className="text-text-neutral-tertiary text-xs">
                  {formatDateTime(event.event_time)} ·{" "}
                  {shortArn(event.user_arn)} · {event.region}
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="flex flex-col gap-2">
        <h4 className="text-text-neutral-primary text-sm font-semibold">
          Open findings in this service
        </h4>
        {findings.length === 0 ? (
          <p className="text-text-neutral-tertiary text-sm">
            No open findings.
          </p>
        ) : (
          <ul className="flex flex-col">
            {findings.map((finding) => (
              <li
                key={finding.finding_id}
                className="border-border-neutral-secondary flex items-start justify-between gap-3 border-t py-2 first:border-t-0"
              >
                <div className="flex min-w-0 flex-col gap-0.5">
                  <Link
                    href={checkFindingsHref(finding.check_id)}
                    className="text-text-neutral-primary text-sm hover:underline"
                  >
                    {finding.title}
                  </Link>
                  <span className="text-text-neutral-tertiary truncate font-mono text-xs">
                    {finding.resource_uid}
                  </span>
                </div>
                <RealtimeBadge descriptor={routeBadge(finding.route)} />
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
