"use client";

import Link from "next/link";

import {
  StatFigure,
  RealtimeSection,
  RealtimeStatCard,
} from "@/components/realtime/realtime-stat-card";
import {
  PanelEmpty,
  PanelFailure,
  PanelLoading,
} from "@/components/realtime/realtime-states";
import { useRealtimeInsight } from "@/components/realtime/use-realtime-insight";
import { Badge } from "@/components/shadcn/badge/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/shadcn/table/table";
import { anomalyHref, formatMoney } from "@/lib/realtime/display";
import {
  REALTIME_INSIGHT_KIND,
  type RealtimeCostDay,
  type RealtimeCostPayloadOn,
} from "@/types/realtime";

const REFRESH_MS = 60_000;

/** Daily spend as bars; the tallest day fills the height. */
function Sparkline({
  days,
  label,
}: {
  days: RealtimeCostDay[];
  label: string;
}) {
  const max = Math.max(...days.map((day) => day.amount), 0.01);
  return (
    <div
      role="img"
      aria-label={label}
      className="flex h-8 w-32 items-end gap-px"
    >
      {days.map((day) => (
        <div
          key={day.day}
          title={`${day.day}: ${formatMoney(day.amount)}`}
          className="bg-bg-data-info min-w-px flex-1 rounded-sm"
          style={{ height: `${Math.max((day.amount / max) * 100, 4)}%` }}
        />
      ))}
    </div>
  );
}

export function CostBody({
  cost,
  providerId,
  demo = false,
}: {
  cost: RealtimeCostPayloadOn;
  providerId: string;
  demo?: boolean;
}) {
  if (cost.series.length === 0 && cost.anomalies.length === 0) {
    return (
      <PanelEmpty
        title="No cost data yet"
        description="Daily cost is fetched from AWS Cost Explorer once the data store is receiving it."
      />
    );
  }
  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <RealtimeStatCard title="Latest day">
          <StatFigure value={formatMoney(cost.total.today)} />
        </RealtimeStatCard>
        <RealtimeStatCard title="Last 30 days">
          <StatFigure value={formatMoney(cost.total.total)} />
        </RealtimeStatCard>
        <RealtimeStatCard title="Anomalies">
          <StatFigure
            value={cost.anomalies.length}
            caption="services spiking"
          />
        </RealtimeStatCard>
      </div>

      {cost.anomalies.length > 0 && (
        <Table aria-label="Cost anomalies">
          <TableHeader>
            <TableRow>
              <TableHead>Service</TableHead>
              <TableHead>Region</TableHead>
              <TableHead>Latest day</TableHead>
              <TableHead>Baseline</TableHead>
              <TableHead>Change</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {cost.anomalies.map((anomaly) => (
              <TableRow key={anomaly.id}>
                <TableCell className="text-text-neutral-primary">
                  <Link
                    href={anomalyHref(anomaly.id, providerId, demo)}
                    className="text-button-tertiary underline underline-offset-4"
                  >
                    {anomaly.service}
                  </Link>
                </TableCell>
                <TableCell>{anomaly.region}</TableCell>
                <TableCell className="tabular-nums">
                  {formatMoney(anomaly.today)}
                </TableCell>
                <TableCell className="tabular-nums">
                  {formatMoney(anomaly.base)}
                </TableCell>
                <TableCell>
                  <Badge variant="warning">
                    {anomaly.ratio}x (+{formatMoney(anomaly.delta)})
                  </Badge>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}

      {cost.series.length > 0 && (
        <Table aria-label="Daily cost by service">
          <TableHeader>
            <TableRow>
              <TableHead>Service</TableHead>
              <TableHead>Region</TableHead>
              <TableHead>Trend</TableHead>
              <TableHead>Latest day</TableHead>
              <TableHead>Baseline</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {cost.series.map((series) => (
              <TableRow key={`${series.service}:${series.region}`}>
                <TableCell className="text-text-neutral-primary">
                  {series.service}
                </TableCell>
                <TableCell>{series.region}</TableCell>
                <TableCell>
                  <Sparkline
                    days={series.days}
                    label={`Daily cost of ${series.service} in ${series.region}`}
                  />
                </TableCell>
                <TableCell className="tabular-nums">
                  {formatMoney(series.latest)}
                </TableCell>
                <TableCell className="tabular-nums">
                  {formatMoney(series.base)}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  );
}

/**
 * Cost series and anomalies. Renders nothing while the signal is off for the
 * account (the API answers `enabled: false`); answers 503 without the data
 * store, shown as a notice.
 */
export function CostPanel({
  providerId,
  demo = false,
}: {
  providerId: string;
  demo?: boolean;
}) {
  const cost = useRealtimeInsight(
    REALTIME_INSIGHT_KIND.COST,
    providerId,
    demo,
    REFRESH_MS,
  );
  if (cost.data && !cost.data.enabled) return null;
  return (
    <RealtimeSection
      title="Cost"
      description="A sudden jump in spend in a service raises the rank of findings in that service. Select a service to see what changed."
    >
      {cost.loading ? (
        <PanelLoading label="Loading cost" />
      ) : cost.failure ? (
        <PanelFailure
          failure={cost.failure}
          onRetry={cost.reload}
          subject="cost"
        />
      ) : cost.data?.enabled ? (
        <CostBody cost={cost.data} providerId={providerId} demo={demo} />
      ) : null}
    </RealtimeSection>
  );
}
