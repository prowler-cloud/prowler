"use client";

import { ArrowLeft } from "lucide-react";
import Link from "next/link";
import { z } from "zod";

import { getRealtimeCostAnomaly, getRealtimeDemo } from "@/actions/realtime";
import {
  AnomalyChart,
  anomalyThreshold,
  baselineOf,
} from "@/components/realtime/anomaly-chart";
import { DemoBanner, DemoProvider } from "@/components/realtime/demo-context";
import { EventsTable } from "@/components/realtime/events-table";
import { RankedFindingsTable } from "@/components/realtime/findings-tab";
import {
  RealtimeSection,
  RealtimeStatCard,
  StatFigure,
} from "@/components/realtime/realtime-stat-card";
import {
  PanelEmpty,
  PanelFailure,
  PanelLoading,
} from "@/components/realtime/realtime-states";
import { useRealtimeResource } from "@/components/realtime/use-realtime-resource";
import { Badge } from "@/components/shadcn/badge/badge";
import { DEMO_ANOMALY_ID } from "@/lib/realtime/demo";
import { formatMoney, parseAnomalyId } from "@/lib/realtime/display";
import type {
  RealtimeAnomalyEvent,
  RealtimeAnomalyPayload,
  RealtimeEvent,
} from "@/types/realtime";

const REFRESH_MS = 60_000;

const isUuid = (value: string) => z.uuid().safeParse(value).success;

const toEvent = (event: RealtimeAnomalyEvent): RealtimeEvent => ({
  id: event.event_id,
  event_time: event.event_time,
  region: event.region,
  event_source: event.event_source,
  event_name: event.event_name,
  user_type: event.user_type,
  user_arn: event.user_arn,
  source_ip: event.source_ip,
  error_code: event.error_code,
  read_only: false,
  provider_id: "",
  detection_status: null,
  rule_id: null,
});

function BackLink({ providerId }: { providerId: string }) {
  return (
    <Link
      href={
        isUuid(providerId)
          ? `/realtime?provider=${encodeURIComponent(providerId)}&tab=findings`
          : "/realtime"
      }
      className="text-button-tertiary inline-flex items-center gap-1 text-sm underline-offset-4 hover:underline"
    >
      <ArrowLeft aria-hidden="true" className="size-4" />
      Back to Realtime
    </Link>
  );
}

export function AnomalyGone({ providerId }: { providerId: string }) {
  return (
    <PanelEmpty
      title="This anomaly is no longer active"
      description="Spend in this service is back under the thresholds, or cost anomalies were turned off for the account."
    >
      <BackLink providerId={providerId} />
    </PanelEmpty>
  );
}

/** The numbers, the chart, the changes and the findings behind one anomaly. */
export function AnomalyBody({
  detail,
  service,
  region,
}: {
  detail: RealtimeAnomalyPayload;
  service: string;
  region: string;
}) {
  const { anomaly, series, thresholds } = detail;
  const latest = series[series.length - 1];
  const today = anomaly?.today ?? latest?.amount ?? 0;
  const baseline = anomaly?.base ?? baselineOf(series);
  const delta = anomaly?.delta ?? today - baseline;
  const ratio = anomaly?.ratio ?? (baseline > 0 ? today / baseline : 0);
  const threshold = anomalyThreshold(baseline, thresholds);

  return (
    <div className="flex flex-col gap-8">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <RealtimeStatCard
          title="Today"
          adornment={
            anomaly ? (
              <Badge variant="warning">Anomaly</Badge>
            ) : (
              <Badge variant="success">Back to normal</Badge>
            )
          }
        >
          <StatFigure value={formatMoney(today)} />
        </RealtimeStatCard>
        <RealtimeStatCard title="Baseline">
          <StatFigure
            value={formatMoney(baseline)}
            caption="trailing daily average"
          />
        </RealtimeStatCard>
        <RealtimeStatCard title="Increase">
          <StatFigure
            value={`+${formatMoney(delta)}`}
            caption={`Needs at least +${formatMoney(thresholds.min_delta)}`}
          />
        </RealtimeStatCard>
        <RealtimeStatCard title="Ratio to baseline">
          <StatFigure
            value={`${Number(ratio.toFixed(1))}x`}
            caption={`Needs at least ${thresholds.min_ratio}x (${formatMoney(threshold)} a day)`}
          />
        </RealtimeStatCard>
      </div>

      <RealtimeSection
        title="Daily spend"
        description={`${service} in ${region}, last 30 days, against its baseline.`}
      >
        <AnomalyChart
          series={series}
          baseline={baseline}
          thresholds={thresholds}
          label={`Daily cost of ${service} in ${region}`}
        />
      </RealtimeSection>

      <RealtimeSection
        title={`Recent changes in ${detail.short_service}`}
        description="Write calls to this service in the last 48 hours. A change from an unexpected actor or IP may explain the spend."
      >
        <EventsTable events={detail.events.map(toEvent)} writesOnly />
      </RealtimeSection>

      <RealtimeSection
        title={`Open findings in ${detail.short_service}`}
        description="Findings in this service rank higher while its cost is spiking."
      >
        <RankedFindingsTable findings={detail.findings} />
      </RealtimeSection>
    </div>
  );
}

export function AnomalyDetail({
  anomalyId,
  providerId,
  demo = false,
}: {
  anomalyId: string;
  providerId: string;
  /** The sample anomaly: the sample data stands in for the account's. */
  demo?: boolean;
}) {
  const parts = parseAnomalyId(demo ? DEMO_ANOMALY_ID : anomalyId);
  const valid = Boolean(parts) && (demo || isUuid(providerId));

  const resource = useRealtimeResource(
    () =>
      demo
        ? getRealtimeDemo("anomaly")
        : getRealtimeCostAnomaly({
            providerId,
            service: parts?.service ?? "",
            region: parts?.region ?? "",
          }),
    demo ? "demo:anomaly" : `anomaly:${providerId}:${anomalyId}`,
    { intervalMs: demo ? undefined : REFRESH_MS, enabled: valid },
  );

  if (!valid || !parts) return <AnomalyGone providerId={providerId} />;

  return (
    <DemoProvider demo={demo}>
      <div className="flex flex-col gap-6">
        {demo && (
          <DemoBanner
            providerId={isUuid(providerId) ? providerId : undefined}
          />
        )}
        <BackLink providerId={providerId} />
        <div className="flex flex-col gap-1">
          <h2 className="text-text-neutral-primary text-xl font-semibold">
            Cost anomaly: {parts.service}
          </h2>
          <p className="text-text-neutral-tertiary text-sm">
            Region {parts.region}
          </p>
        </div>

        {resource.loading ? (
          <PanelLoading label="Loading the anomaly" />
        ) : resource.failure?.status === 404 ? (
          <AnomalyGone providerId={providerId} />
        ) : resource.failure ? (
          <PanelFailure
            failure={resource.failure}
            onRetry={resource.reload}
            subject="the anomaly"
          />
        ) : resource.data ? (
          <AnomalyBody
            detail={resource.data}
            service={parts.service}
            region={parts.region}
          />
        ) : null}
      </div>
    </DemoProvider>
  );
}
